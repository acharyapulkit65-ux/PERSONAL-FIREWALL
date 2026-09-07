#!/usr/bin/env python3
"""
Personal Firewall - a Python-based traffic monitor and packet filter.

Two modes:
  monitor  - sniffs traffic with Scapy and logs what WOULD be allowed/blocked.
             Safe, read-only, works on any OS with a supported pcap backend.
  enforce  - Linux only. Uses NFQUEUE (via iptables + netfilterqueue) to
             actually accept/drop live packets according to the rules.

Usage:
  # Safe, read-only mode (recommended to start with):
  sudo python3 firewall.py monitor --iface eth0 --rules rules.json

  # Active enforcement (Linux, requires root + NFQUEUE iptables rule, see README):
  sudo python3 firewall.py enforce --queue-num 1 --rules rules.json

Run in a VM or isolated network while developing -- a misconfigured
enforce-mode rule set can cut off your own connectivity.
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("personal_firewall")


def setup_logging(log_file: str = "firewall.log", verbose: bool = False) -> None:
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)


# ---------------------------------------------------------------------------
# Packet abstraction - so the rule engine doesn't care whether the packet
# came from Scapy's sniff() or from a netfilterqueue callback.
# ---------------------------------------------------------------------------


@dataclass
class PacketInfo:
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str          # "tcp", "udp", "icmp", or "other"
    src_port: Optional[int]
    dst_port: Optional[int]
    direction: str          # "inbound", "outbound", or "unknown"
    length: int

    def summary(self) -> str:
        port_info = ""
        if self.src_port or self.dst_port:
            port_info = f" {self.src_port}->{self.dst_port}"
        return (f"{self.protocol.upper()} {self.src_ip}->{self.dst_ip}"
                f"{port_info} ({self.length}B) [{self.direction}]")


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Loads rules from JSON and decides allow/block for a given packet."""

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.default_policy = "allow"
        self.rules = []
        self.load_rules()

    def load_rules(self) -> None:
        path = Path(self.rules_path)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with open(path, "r") as f:
            data = json.load(f)

        self.default_policy = data.get("default_policy", "allow")
        self.rules = data.get("rules", [])
        logger.info(f"Loaded {len(self.rules)} rules "
                    f"(default policy: {self.default_policy})")

    def reload(self) -> None:
        """Re-read the rules file without restarting the process."""
        self.load_rules()

    @staticmethod
    def _rule_matches(rule: dict, pkt: PacketInfo) -> bool:
        # Protocol check
        proto = rule.get("protocol", "any")
        if proto != "any" and proto != pkt.protocol:
            return False

        # Direction check
        direction = rule.get("direction", "any")
        if direction != "any" and direction != pkt.direction:
            return False

        # IP checks
        if "src_ip" in rule and rule["src_ip"] != pkt.src_ip:
            return False
        if "dst_ip" in rule and rule["dst_ip"] != pkt.dst_ip:
            return False

        # Port checks
        if "src_port" in rule and rule["src_port"] != pkt.src_port:
            return False
        if "dst_port" in rule and rule["dst_port"] != pkt.dst_port:
            return False

        return True

    def evaluate(self, pkt: PacketInfo) -> tuple[str, Optional[str]]:
        """
        Returns (action, rule_name). action is "allow" or "block".
        Rules are evaluated top-down; first match wins. Falls back to
        default_policy if nothing matches.
        """
        for rule in self.rules:
            if self._rule_matches(rule, pkt):
                return rule.get("action", "allow"), rule.get("name", "unnamed rule")
        return self.default_policy, None


# ---------------------------------------------------------------------------
# Packet parsing (Scapy)
# ---------------------------------------------------------------------------


def parse_scapy_packet(raw_pkt, local_ips: set) -> Optional[PacketInfo]:
    from scapy.layers.inet import IP, TCP, UDP, ICMP

    if not raw_pkt.haslayer(IP):
        return None

    ip_layer = raw_pkt[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst

    if raw_pkt.haslayer(TCP):
        proto = "tcp"
        sport, dport = raw_pkt[TCP].sport, raw_pkt[TCP].dport
    elif raw_pkt.haslayer(UDP):
        proto = "udp"
        sport, dport = raw_pkt[UDP].sport, raw_pkt[UDP].dport
    elif raw_pkt.haslayer(ICMP):
        proto = "icmp"
        sport, dport = None, None
    else:
        proto = "other"
        sport, dport = None, None

    if local_ips:
        if src_ip in local_ips and dst_ip not in local_ips:
            direction = "outbound"
        elif dst_ip in local_ips and src_ip not in local_ips:
            direction = "inbound"
        else:
            direction = "unknown"
    else:
        direction = "unknown"

    return PacketInfo(
        src_ip=src_ip, dst_ip=dst_ip, protocol=proto,
        src_port=sport, dst_port=dport, direction=direction,
        length=len(raw_pkt),
    )


def get_local_ips() -> set:
    """Best-effort collection of this machine's IPs, used to infer direction."""
    import socket
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        # Trick to get the primary outbound-facing IP without sending data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    ips.add("127.0.0.1")
    return ips


# ---------------------------------------------------------------------------
# Monitor mode - read-only, cross-platform
# ---------------------------------------------------------------------------


def run_monitor(iface: Optional[str], rules_path: str) -> None:
    from scapy.all import sniff

    engine = RuleEngine(rules_path)
    local_ips = get_local_ips()
    logger.info(f"Local IPs detected: {local_ips}")
    logger.info("Starting MONITOR mode (read-only, no packets are dropped). "
                 "Ctrl+C to stop.")

    stats = {"allow": 0, "block": 0}

    def handle(raw_pkt):
        pkt = parse_scapy_packet(raw_pkt, local_ips)
        if pkt is None:
            return
        action, rule_name = engine.evaluate(pkt)
        stats[action] = stats.get(action, 0) + 1

        if action == "block":
            logger.warning(f"[WOULD BLOCK] {pkt.summary()} "
                            f"(rule: {rule_name or 'default policy'})")
        else:
            logger.debug(f"[ALLOW] {pkt.summary()}")

    try:
        sniff(iface=iface, prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info(f"Monitor stopped. Allowed: {stats.get('allow', 0)}, "
                     f"Blocked (simulated): {stats.get('block', 0)}")


# ---------------------------------------------------------------------------
# Enforce mode - Linux only, actually drops packets via NFQUEUE
# ---------------------------------------------------------------------------


def run_enforce(queue_num: int, rules_path: str) -> None:
    """
    Requires: pip install netfilterqueue  (Linux only, needs libnetfilter-queue-dev)
    And an iptables rule directing traffic into the queue, e.g.:
        sudo iptables -I INPUT -j NFQUEUE --queue-num 1
        sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
    See README.md for full setup and how to remove these rules afterward.
    """
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        logger.error("netfilterqueue is not installed. Run: "
                      "pip install netfilterqueue --break-system-packages "
                      "(also requires libnetfilter-queue-dev on the system)")
        sys.exit(1)

    from scapy.all import IP as ScapyIP

    engine = RuleEngine(rules_path)
    local_ips = get_local_ips()
    logger.info(f"Local IPs detected: {local_ips}")
    logger.info(f"Starting ENFORCE mode on NFQUEUE #{queue_num}. "
                 "Packets will be dropped/accepted live. Ctrl+C to stop.")

    stats = {"allow": 0, "block": 0}

    def callback(nf_packet):
        raw = ScapyIP(nf_packet.get_payload())
        pkt = parse_scapy_packet(raw, local_ips)

        if pkt is None:
            nf_packet.accept()
            return

        action, rule_name = engine.evaluate(pkt)
        stats[action] = stats.get(action, 0) + 1

        if action == "block":
            logger.warning(f"[BLOCKED] {pkt.summary()} "
                            f"(rule: {rule_name or 'default policy'})")
            nf_packet.drop()
        else:
            logger.debug(f"[ALLOW] {pkt.summary()}")
            nf_packet.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, callback)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()
        logger.info(f"Enforce mode stopped. Allowed: {stats.get('allow', 0)}, "
                     f"Blocked: {stats.get('block', 0)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="A simple personal firewall.")
    sub = parser.add_subparsers(dest="mode", required=True)

    mon = sub.add_parser("monitor", help="Read-only: log allow/block decisions")
    mon.add_argument("--iface", default=None, help="Network interface to sniff")
    mon.add_argument("--rules", default="rules.json", help="Path to rules JSON")

    enf = sub.add_parser("enforce", help="Linux only: actually drop packets via NFQUEUE")
    enf.add_argument("--queue-num", type=int, default=1, help="NFQUEUE number")
    enf.add_argument("--rules", default="rules.json", help="Path to rules JSON")

    parser.add_argument("--log-file", default="firewall.log")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.log_file, args.verbose)

    if args.mode == "monitor":
        run_monitor(args.iface, args.rules)
    elif args.mode == "enforce":
        run_enforce(args.queue_num, args.rules)


if __name__ == "__main__":
    main()

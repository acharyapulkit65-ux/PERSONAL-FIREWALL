# Personal Firewall (Python + Scapy)

A rule-based personal firewall you can run in two modes:

- **monitor** — read-only. Sniffs traffic and logs what *would* be allowed
  or blocked, without touching real packets. Safe to run anywhere, great
  for testing rules.
- **enforce** — Linux only. Uses `NFQUEUE` (kernel netfilter) to actually
  accept/drop live packets according to your rules.

Start with `monitor` mode. Only move to `enforce` once you trust your
rule set — a bad rule can cut off your own network access.

## 1. Install dependencies

```bash
pip install scapy --break-system-packages

# only needed for enforce mode (Linux):
sudo apt install libnetfilter-queue-dev
pip install netfilterqueue --break-system-packages
```

## 2. Edit your rules

Rules live in `rules.json`. Each rule is checked top-down; the first
match wins. If nothing matches, `default_policy` applies.

```json
{
  "name": "Block Telnet",
  "action": "block",
  "protocol": "tcp",
  "dst_port": 23,
  "direction": "any"
}
```

Fields:
- `action`: `"allow"` or `"block"`
- `protocol`: `"tcp"`, `"udp"`, `"icmp"`, or `"any"`
- `direction`: `"inbound"`, `"outbound"`, or `"any"`
- `src_ip` / `dst_ip` / `src_port` / `dst_port`: optional, omit to match any

## 3. Run monitor mode (safe, recommended first)

```bash
sudo python3 firewall.py monitor --iface eth0 --rules rules.json -v
```

Watch `firewall.log` (and stdout) for `[ALLOW]` / `[WOULD BLOCK]` lines.
Adjust `rules.json` until the decisions look right for your network.

## 4. Run enforce mode (Linux, actually blocks traffic)

First, redirect traffic into the NFQUEUE the script listens on:

```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
```

Then run:

```bash
sudo python3 firewall.py enforce --queue-num 1 --rules rules.json -v
```

**To remove the iptables rules afterward** (important — otherwise all
traffic keeps queuing to a process that isn't running):

```bash
sudo iptables -D INPUT -j NFQUEUE --queue-num 1
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
```

## 5. Safety notes

- Test in a VM or isolated network segment first.
- Keep a console/physical session open while testing `enforce` mode, in
  case a rule locks out your SSH/remote access.
- `direction` inference relies on detecting your machine's local IPs; on
  multi-homed hosts or behind NAT it may be imperfect — verify against
  known traffic before trusting it.

## Extending this project

Ideas for next steps, roughly in order of difficulty:
1. Add stateful tracking (allow return traffic for connections you initiated)
2. Add rate limiting / simple port-scan detection (many SYNs from one IP in a short window)
3. Add a config hot-reload (watch `rules.json` for changes)
4. Add a small web dashboard (Flask) showing live stats and letting you add/remove rules
5. Add GeoIP-based blocking using a local GeoIP database

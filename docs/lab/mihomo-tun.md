# Mac Linux VM + Mihomo TUN Lab

This lab keeps `dynet` inside its zero-intrusion boundary:

- Lima owns the Linux VM.
- Mihomo owns TUN, DNS hijack, routing, and nftables/iptables inside the VM.
- `dynet` only exposes host-side DNS and SOCKS5 ingress listeners.

The target flow is:

```text
Linux app in VM
  -> Mihomo TUN capture
  -> Mihomo DNS module -> host dynet DNS 127.0.0.1:1053
  -> Mihomo SOCKS5 proxy -> host dynet SOCKS5 127.0.0.1:1080
  -> dynet forwarding
```

Lima's default user-mode network exposes the macOS host loopback to the guest
as `192.168.5.2` and `host.lima.internal`. The sample Mihomo config uses the
IP address to avoid depending on DNS before the DNS path is validated.

The sample uses Mihomo `redir-host` DNS mode so upstream DNS queries remain
observable by `dynet`. Host-side `dynet` uses a DNS-over-HTTPS upstream in the
sample `dynet-lab.toml`, which keeps runtime resolution independent from local
UDP/53 fake-DNS interception.

Inside the VM, point systemd-resolved at Mihomo's local DNS listener:

```bash
limactl shell dynet-lab sudo resolvectl dns eth0 127.0.0.1
limactl shell dynet-lab sudo resolvectl domain eth0 '~.'
```

## Timing Model

Reasonable targets:

- First-ever setup with Homebrew, Lima image download, OS packages, and Mihomo
  binary download: network-bound; it may exceed 10 minutes. In one local run,
  the Ubuntu image download alone took about 10 minutes and 45 seconds.
- Recreating the lab after the Lima image and Mihomo artifact are cached:
  target under 10 minutes.
- Hot restart with the VM already running: `dynet` + Mihomo process restart
  target under 1 second.
- Starting a stopped VM is not a 1 second operation; expect several seconds.

Treat the hot path as process restart, not VM boot.

## Host Setup

Install Lima if needed:

```bash
brew install lima
```

Create and start the VM:

```bash
limactl start --name dynet-lab docs/lab/lima-dynet.yaml
```

The sample VM intentionally avoids `apt-get update` in the startup path. Keep
network package installation out of `limactl start` if cold-start timing matters.

Build `dynet` once on the host:

```bash
cargo build --locked -p dynet-cli
```

Start host-side `dynet`:

```bash
DYNET_RUNTIME_DB=target/dynet-lab.sqlite \
  target/debug/dynet --config docs/lab/dynet-lab.toml
```

The sample sets `ingress.socks5.udp_advertise_ip = "192.168.5.2"`. This is
needed because a SOCKS5 UDP ASSOCIATE reply must advertise an address reachable
from the VM; advertising host `127.0.0.1` would make Mihomo send UDP packets to
the VM loopback instead of host-side `dynet`.

The sample `dynet-lab.toml` uses a graph-shaped forwarding config with one
direct audit outlet node in the default smart group. For provider-node tests,
copy the file to untracked `dynet.toml` and replace the forwarding graph with
the local nodes/groups under test. Use `next = "<group>"` for group-to-group
TCP composition in connection direction; for example, `Tunnel.next = "Private"`
means traffic first uses the Tunnel group's selected dialer node, then reaches
the Private group's selected business egress node.

If a capture frontend sends SOCKS5 TCP/UDP traffic to a previously observed
fake-IP target, `dynet` restores the domain from its observed DNS map and
re-resolves it before selecting and forwarding the egress target. Configure at
least one real-answer DNS upstream, such as the sample DoH upstream, otherwise
the restored target can still resolve back to a fake address.

## VM Setup

Optional debug tools:

```bash
limactl shell dynet-lab sudo apt-get update
limactl shell dynet-lab sudo apt-get install -y --no-install-recommends \
  curl iproute2 iptables jq nftables tcpdump
```

Install a Mihomo binary in the VM using the project's release artifact for the
guest architecture, then verify:

```bash
limactl shell dynet-lab mihomo -v
```

Install the sample config:

```bash
limactl copy docs/lab/mihomo-dynet.yaml dynet-lab:/tmp/mihomo-dynet.yaml
limactl shell dynet-lab sudo install -m 0644 /tmp/mihomo-dynet.yaml /etc/mihomo/dynet.yaml
```

Start Mihomo in the VM:

```bash
limactl shell dynet-lab sudo mihomo -d /etc/mihomo -f /etc/mihomo/dynet.yaml
```

Confirm that Mihomo's TUN routing table is active for ordinary outbound
traffic:

```bash
limactl shell dynet-lab ip route get 1.1.1.1
```

The route should use `dev Meta`. If it instead uses `dev eth0`, Mihomo created
the TUN route table but did not install a policy rule for normal VM traffic.
Add the rule:

```bash
limactl shell dynet-lab sudo ip rule add pref 9000 lookup 2022
limactl shell dynet-lab ip route get 1.1.1.1
```

The host bridge must still bypass TUN:

```bash
limactl shell dynet-lab ip route get 192.168.5.2
```

This should remain on `dev eth0`; otherwise Mihomo cannot reach host-side
`dynet`.

For repeated runs, keep the VM running and restart only the two processes:

```bash
pkill dynet || true
DYNET_RUNTIME_DB=target/dynet-lab.sqlite \
  target/debug/dynet --config docs/lab/dynet-lab.toml
```

```bash
limactl shell dynet-lab sudo pkill mihomo || true
limactl shell dynet-lab sudo mihomo -d /etc/mihomo -f /etc/mihomo/dynet.yaml
```

To use the full local `vpn-config` node and rule set for experiments, generate
the ignored local config first:

```bash
scripts/sync-vpn-config.py
```

The generated `dynet.toml` contains local node credentials and must stay
untracked. The script maps the Clash rule buckets into dynet groups, keeps
`MATCH` on `Private`, maps `Tunnel.next` to `Private`, and skips unsupported
entries such as SSR nodes or reject-only rules instead of pretending they are
enforceable. After syncing, start dynet with:

```bash
DYNET_RUNTIME_DB=target/dynet-lab.sqlite \
  target/debug/dynet --config dynet.toml
```

## Validation

From the host, verify `dynet` is up:

```bash
curl -fsS http://127.0.0.1:9977/api/v1/health
```

From the VM, verify it can reach host-side `dynet`:

```bash
limactl shell dynet-lab curl -fsS http://192.168.5.2:9977/api/v1/health
```

With Mihomo running, issue DNS and TCP traffic from inside the VM:

```bash
limactl shell dynet-lab getent hosts example.com
limactl shell dynet-lab curl -fsS --max-time 10 http://example.com/ >/dev/null
```

Then inspect host-side events:

```bash
curl -fsS http://127.0.0.1:9977/api/v1/events | jq '.events[-20:]'
```

For repeatable black-box validation with `dynet` and Mihomo already running:

```bash
scripts/smoke/lab-blackbox.sh
```

For browser-workflow validation, install Playwright in the VM once:

```bash
limactl shell dynet-lab sudo apt-get update
limactl shell dynet-lab sudo apt-get install -y --no-install-recommends \
  nodejs npm libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
  libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
  libxfixes3 libxrandr2 libgbm1 libasound2t64 libpango-1.0-0 \
  libcairo2 libatspi2.0-0 libgtk-3-0 fonts-liberation ca-certificates
limactl shell dynet-lab sudo npm install -g playwright
limactl shell dynet-lab playwright install chromium
```

Then run a repeatable browser smoke:

```bash
scripts/smoke/lab-playwright.sh
```

This opens the configured URLs with headless Chromium from inside the VM,
stores screenshots under `/tmp/dynet-playwright-lab`, and verifies that dynet
observes traffic sessions plus matrix shadow decisions for each top-level host.
It waits briefly after browser completion so TCP close events and byte counters
can settle before API inspection.

Optional environment overrides:

```bash
DYNET_LAB_DOMAINS="example.com example.org cloudflare.com" \
DYNET_LAB_TCP_URLS="http://example.com/ http://example.org/" \
DYNET_LAB_UDP_HOST=1.1.1.1 \
DYNET_LAB_UDP_PORT=443 \
scripts/smoke/lab-blackbox.sh
```

```bash
DYNET_LAB_PLAYWRIGHT_URLS="https://example.com/ https://www.iana.org/" \
DYNET_LAB_PLAYWRIGHT_EXPECT_GROUPS=Tunnel,Private \
scripts/smoke/lab-playwright.sh
```

Use `DYNET_LAB_GUEST_CONTROL_URL` if the VM reaches the host at an address
other than Lima's default `http://192.168.5.2:9977`.
Use `DYNET_LAB_EXPECT_TCP_GROUPS=Tunnel,Private` to assert the TCP graph trace
for a Tunnel group that exits through a Private group.
The script ensures the Mihomo TUN route rule by default. Set
`DYNET_LAB_ENSURE_TUN_RULE=0` to disable this check.
It also flushes VM systemd-resolved DNS cache before taking the event baseline
and uses `resolvectl query --cache=no` for DNS probes when available. DNS
events are treated as auxiliary evidence because repeated VM/browser runs can
hit resolver caches. The default hard assertions focus on TCP/UDP sessions and
selection metadata. Set `DYNET_LAB_REQUIRE_DNS_EVIDENCE=1` for stricter DNS
evidence checks, or `DYNET_LAB_FLUSH_DNS_CACHE=0` to disable the cache flush.

Expected event evidence:

- `dns-query` and `dns-response` for VM name resolution.
- `tcp-accept` and `tcp-close` with `inbound = "socks5"` for VM TCP traffic.
- `udp-datagram` with `inbound = "socks5"` when a VM UDP client sends traffic
  through Mihomo.

## Failure Checks

If the VM cannot reach `dynet`, first check the host process:

```bash
curl -fsS http://127.0.0.1:9977/api/v1/health
limactl shell dynet-lab getent hosts host.lima.internal
limactl shell dynet-lab curl -v http://192.168.5.2:9977/api/v1/health
```

If Mihomo starts but traffic loops or stalls, confirm that host loopback is
excluded from the TUN route:

```bash
limactl shell dynet-lab ip route get 192.168.5.2
```

If public UDP or HTTP/3 traffic does not produce dynet SOCKS5 UDP events,
confirm that ordinary outbound traffic uses Mihomo's TUN table:

```bash
limactl shell dynet-lab ip rule
limactl shell dynet-lab ip route show table 2022
limactl shell dynet-lab ip route get 1.1.1.1
```

The route to `1.1.1.1` should use `dev Meta`. If not, add:

```bash
limactl shell dynet-lab sudo ip rule add pref 9000 lookup 2022
```

If DNS events are missing, confirm Mihomo is hijacking DNS and forwarding
queries to `udp://192.168.5.2:1053`:

```bash
limactl shell dynet-lab sudo tcpdump -ni any host 192.168.5.2 and port 1053
```

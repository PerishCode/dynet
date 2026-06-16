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
  -> dynet outbound
```

Lima's default user-mode network exposes the macOS host loopback to the guest
as `192.168.5.2` and `host.lima.internal`. The sample Mihomo config uses the
IP address to avoid depending on DNS before the DNS path is validated.

The sample uses Mihomo `redir-host` DNS mode so upstream DNS queries remain
observable by `dynet`. `fake-ip` can be useful for other proxy labs, but it can
hide DNS forwarding from this experiment by answering locally.

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

The sample `dynet-lab.toml` uses direct outbound. For provider-node tests, copy
the file to untracked `dynet.toml` and replace only the `[outbound]` section
with the local node under test.

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

If DNS events are missing, confirm Mihomo is hijacking DNS and forwarding
queries to `udp://192.168.5.2:1053`:

```bash
limactl shell dynet-lab sudo tcpdump -ni any host 192.168.5.2 and port 1053
```

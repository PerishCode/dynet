# dynet Full Takeover Design

`dynet` has one product runtime shape: it fully owns DNS, UDP, and TCP capture,
forwarding decisions, egress execution, and observability feedback.

Linux cold start is TUN-first, dual-stack-capable, and intentionally scoped to
router or VM environments. IPv6 participation is explicit; host IPv6 remains
caller-owned. Desktop and mobile capture are future backend work.

## Runtime Shape

```text
dynet service apply
  -> reconcile a strictly owned systemd/procd service artifact
  -> doctor checks isolated host integration points
  -> apply --auto creates only dynet-owned .d fragments
  -> Linux TUN backend owns dynet0 and routing state
  -> DNS / UDP / TCP enter dynet
  -> runtime classifies target and correlates DNS/IP context
  -> RuntimeState::select chooses the forwarding graph
  -> egress executes direct or protocol-backed forwarding
  -> events update sessions, DNS observations, and matrix stats
```

## Non-Negotiable Boundaries

- No partial product modes.
- No external capture frontend as the target architecture.
- No fallback to direct global file overwrites.
- No host-wide IPv6 disable/drop policy.
- No implicit firewall admission or port-53 mapping.
- No overwrite or removal of foreign route/nft/service artifacts.
- No routing or nftables business decisions outside dynet.

## IPv6 and Caller Integration Contract

- `[ipv6].enabled = false` means dynet does not participate in IPv6. It does not
  mutate host IPv6 or install a deny rule.
- `[ipv6].enabled = true` defaults IPv6 to allow. Matching forwarding rules may
  set `ipv6 = allow`, `deny`, or `inherit`; the selected graph still determines
  egress, and no cross-group/direct fallback is allowed.
- Nodes can declare `ipv6 = false`. IPv6 selection fails explicitly when the
  chosen group has no eligible node.
- Dynet capture helpers only mark TCP/UDP. ICMPv6 and other protocols remain
  outside the product boundary.
- Rule-level deny is routing/DNS policy, not a security boundary during
  fail-open cleanup. The caller firewall owns hard security policy.
- The stable integration ABI is mark `0x40000000/0x40000000`, rule priority
  `10000`, route table ID `51880`, and nft output priority `-150`. Marking ORs
  the reserved bit and preserves all unrelated caller bits.
- Port 53 remains caller-owned. `dns-mapping apply` is an optional explicit
  helper scoped to a configured interface; it touches neither firewall
  admission, DHCP, dnsmasq, UCI, nor fw4. Service start never applies it.
- Owned hooks/mappings are cleaned before startup and after terminal runtime
  exit. Foreign artifacts are left untouched and reported as hard collisions.

## Isolation Model

Host takeover must use dynet-owned isolated carriers. Exact carriers can evolve
as Linux support matures, but unsupported isolation is a hard failure.

Initial carriers:

- `/etc/sysctl.d/90-dynet.conf`
- `/etc/iproute2/rt_tables.d/dynet.conf`
- dynet-owned nftables table, initially `inet dynet`
- `dynet0` TUN device
- systemd service or drop-in paths under `/etc/systemd/system`
- OpenWrt procd init scripts under `/etc/init.d`

`dynet apply --auto` may create missing dynet-owned fragments when the parent
carrier exists. It must not edit `/etc/sysctl.conf`, `/etc/iproute2/rt_tables`,
the distribution nftables root config, or resolver files in place.

## Service Lifecycle

`dynet run` is always a foreground process. `dynet service` is an optional,
backend-neutral Linux control plane with systemd and OpenWrt procd backends. It
owns exactly one generated artifact, records a payload hash, writes atomically,
and refuses symlinks, foreign content, and external drift. Apply enables boot
start and starts an inactive service; changing an active service definition
reports restart-required instead of silently replacing the running process.
Every manager-driven spawn first cleans stale hooks and reconciles the takeover
skeleton with `apply --auto`. This is required because an API listener can be
healthy while a newly created TUN interface is still DOWN; service health must
include both the control API and takeover runtime readiness.

The configured service account must be stable and non-root. Capture hook apply
resolves that account and verifies the nft output bypass against its current
UID. Both backends clean hooks before runtime startup and after terminal exit.
The systemd backend uses privileged pre/post commands around a non-root runtime;
the procd backend keeps a privileged supervisor, drops the child UID/GID while
retaining only `CAP_NET_ADMIN`, forwards HUP/TERM/INT, enforces a shutdown
timeout, and cleans hooks plus optional DNS mappings before returning to procd
respawn. It does not require `setcap` on OpenWrt. For capture-enabled starts it
pre-opens `/dev/net/tun` as root, passes the validated non-CLOEXEC descriptor to
the child through a private process ABI, and drops the supervisor copy after
spawn. The child still performs `TUNSETIFF` with its retained capability; global
device permissions remain untouched.

Runtime reload and shutdown remain dynet responsibilities. HUP publishes only a
fully valid hot-reload generation and records applied, no-op, invalid, or
restart-required audit outcomes. TERM/INT stop ingress, bound connection drain,
flush persistence, and exit cleanly.

Persistent observability is resource-bounded for router use. Defaults are 24
hours and 64 MiB, both configurable. Maintenance prunes expired completed data,
protects active sessions from time-based pruning, evicts oldest observations
under size pressure, caps SQLite pages, and checkpoints a bounded WAL. No packet
payloads or credentials are stored.

## Module Boundary

`dynet-capture` owns capture backend and host takeover lifecycle. It emits
normalized captured flow context into the existing runtime and egress core.

The normalized boundary is intentionally platform-neutral:

```text
CapturedFlow {
  peer,
  target: packet destination or observed-DNS target,
  transport: DNS/UDP, DNS/TCP, TCP, or UDP
}
```

Linux TUN is the first backend that produces this shape. Future platform
backends must produce the same shape instead of reaching into runtime selection
or matrix internals.

The runtime core remains responsible for:

- target context
- DNS observation
- route rule matching
- group/node selection
- session and error recording
- matrix feedback

Linux TUN details must not leak into selection, matrix, or protocol egress
implementations.

## First Implementation Slice

1. Add lifecycle commands: `plan`, `doctor`, `status`, `apply --auto`,
   `reconcile`, `cleanup`.
2. Add Linux `.d` capability probing and hard-fail reporting.
3. Add dynet-owned fragment creation for safe, isolated files only.
4. Add TUN lifecycle skeleton: create `dynet0`, bring it up, create the
   `inet dynet` nftables table with inert `bypass` / `dns` / `tcp` / `udp`
   chains, and clean those artifacts up.
5. Add local packet parsing for IPv4/IPv6 TCP / UDP / DNS into `CapturedFlow`.
6. Add real TUN open / `TUNSETIFF` binding and packet read/write primitives,
   validated only inside the VM with `dynet tun-probe dynet0`.
7. Add a VM-only output hook slice: route marked VM-originated TCP/UDP traffic
   to `dynet0`, with explicit SSH/LAN/loopback/service-UID bypasses and a
   dedicated cleanup command.
8. Validate a VM-only userspace stack POC that consumes TCP / UDP / DNS from
   `dynet0` and direct-forwards responses back into the local kernel.
9. Connect DNS / UDP / TCP captured flows into the existing runtime and egress
   paths.
10. Promote the runtime-connected TUN path into disabled-by-default
   `[capture.tun]` mode owned by `dynet run`.
11. Validate first inside a Proxmox VM, then with an experimental client that
   points gateway and DNS at the dynet VM.

The lifecycle skeleton deliberately stops before installing default routes,
policy rules, nft hooks, or packet redirection. The nft chains created by
`apply --auto` are inert because they have no hooks. `hooks apply` is a separate
VM-only stage for the first route and nft hook probe, so the skeleton stays
safe and the hook layer can be removed independently with `hooks cleanup`.

The local-safe packet slice parses IPv4 and IPv6 TCP / UDP / DNS packet metadata from
bytes and maps it into normalized captured flow context. Real `/dev/net/tun`
open/read/write and capture hooks remain VM-only. Current hook validation is
limited to VM-originated output traffic; router-forwarded prerouting/forwarding
capture remains a later slice after the userspace TUN loop consumes packets.

## VM POC Notes

The first userspace-stack POC uses `ipstack 1.0.0` behind the VM-only
`dynet ipstack-poc` command. It is intentionally direct egress only: it proves
the TUN consumption and kernel reinjection path before connecting captured
flows to runtime selection and protocol-backed egress.

Historical IPv4 validation on `dynet.lan` on 2026-07-04 (superseded by the
dual-stack contract above):

- The historical build disabled IPv6 in its sysctl fragment. Current dynet no
  longer writes any `net.ipv6.conf.*.disable_ipv6` value; callers migrating a
  live host must explicitly undo stale runtime sysctls left by that old build.
- `hooks apply` installs the fwmark rule at priority `10000`, before Linux's
  default `main` rule. The earlier `51880` priority sits after `main` and lets
  marked packets escape through the normal default route.
- With `ipstack-poc --max-tcp=1 --max-udp=0`, a root
  `curl http://1.1.1.1/` probe returned HTTP `301` through the TUN path. The
  POC logged `client_to_upstream=71` and `upstream_to_client=386`.
- With `ipstack-poc --max-tcp=0 --max-udp=1`, a root UDP DNS query to
  `1.1.1.1:53` returned a valid response for `example.com`
  (`rcode=0`, `answers=2`).
- `ipstack-runtime-poc` then replaced the direct POC sockets with existing
  runtime selection plus `GraphEgress`. A root `curl http://1.1.1.1/` probe
  returned HTTP `301` through the TUN -> runtime -> graph path with
  `client_to_upstream=71` and `upstream_to_client=386`.
- The runtime UDP path also passed: a root UDP DNS query to `1.1.1.1:53` for
  `example.com` returned `rcode=0`, `answers=2` through TUN -> runtime ->
  graph egress.
- `hooks cleanup` removed the output hook, priority `10000` fwmark rule, and
  `dynet` route-table default after each validation window, leaving steady
  state with no capture hook, policy route rule, or `dynet` route.

Validated on `dynet.lan` on 2026-07-05:

- `dynet run --config <temp>` can start a long-running TUN capture runner when
  `[capture.tun].enabled = true`. The mode is disabled by default.
- `dynet run` only consumes `dynet0`; it does not install the output hook,
  fwmark rule, or `dynet` route-table default. Those remain explicit
  `hooks apply` / `hooks cleanup` operations.
- A root `curl http://1.1.1.1/` probe returned HTTP `301` through
  TUN -> runtime -> graph egress. Runtime events recorded `tcp-accept` and
  `tcp-close` with `inbound=tun`, `clientToUpstreamBytes=71`, and
  `upstreamToClientBytes=386`.
- A root UDP DNS query to `1.1.1.1:53` for `example.com` returned `rcode=0`,
  `answers=2` through the same long-running runner. Runtime events recorded
  TUN UDP datagrams and `udp-session-close`.
- Probes must run as root in the current VM output-hook slice; traffic from the
  `service` UID is intentionally bypassed so dynet's own egress is not
  recaptured.
- Cleanup again left steady state with no output hook, no priority `10000`
  fwmark rule, and no `dynet` route-table default.

Provider validation on `dynet.lan` on 2026-07-05:

- The intended target scenario is shudong airport nodes for `Common` and
  `Tunnel`, plus `Private Lisahost US` for `Private` with Private dialing
  through Tunnel. The earlier Bandwagon beta profile validation is only an
  adjacent proof, not the target dynet scenario.
- A gitignored shudong config generated from `vpn-config` can express
  `Common -> shudong VMess`, `Tunnel -> shudong VMess -> Private`, and
  `Private -> Private Lisahost US Shadowsocks`, with `[capture.tun]` still
  disabled by default. The generator reads airport nodes from the airport
  proxy-provider and Private nodes from inline `perish.yml` proxies. shudong
  SSR nodes are skipped because dynet does not support SSR yet.
- With `[capture.tun]` enabled only by environment override, a root TCP probe to
  `1.0.0.1:80` returned HTTP `301` through the shudong provider path. Runtime
  events recorded `inbound=tun`, `selectionGroups=Common`,
  `selectionNodes=shudong-us-01`, `nodeProtocol=vmess`, and `tcp-close`.
- Direct DNS upstreams in the VM returned polluted or abnormal
  `www.google.com` A records during the Private-domain attempt. For this slice,
  the Private graph was therefore validated with a temporary
  `ip-cidr 1.1.1.1/32 -> Tunnel` rule instead of relying on DNS observation.
- A root TCP probe to `1.1.1.1:80` returned HTTP `301` through the chained path.
  Runtime events recorded `selectionGroups=Tunnel,Private` and
  `selectionNodes=shudong-us-01,private-lisahost-us`, proving the Private
  egress was dialed through a shudong Tunnel node.
- Follow-up fixed protocol-backed captured TCP observability: Shadowsocks,
  Trojan, VMess, and VLESS egress now return `closeReason=idle-timeout` when
  plaintext byte counters stay idle for the capture timeout. This is covered by
  `captured_tcp_protocol_idle`.
- Revalidated on the dedicated service.lan dynet VM after the generator learned
  the current `vpn-config` layout. A generated provider config contained 66
  airport nodes, 2 Private nodes, and 638 routed rules. For the live SS2022
  check, a temporary VM-only config routed `1.1.1.1/32 -> Tunnel` and pinned the
  `Private` group to `private-002-Private-Lisahost-US`. A root
  VM-originated keep-alive TCP probe returned HTTP `301`; runtime events
  recorded `inbound=tun`, `selectionGroups=Tunnel,Private`,
  `selectionNodes=airport-003-jms-us-03,private-002-Private-Lisahost-US`,
  `nodeProtocol=ss`, `clientToUpstreamBytes=57`,
  `upstreamToClientBytes=386`, and `closeReason=idle-timeout`.
- Cleanup again left the VM with no output hook, no priority `10000` fwmark
  rule, and no `dynet` route-table default.

Dedicated service.lan VM validation on 2026-07-09:

- `service.lan` now provisions a dedicated Proxmox VM `170` /
  `service-lan-dynet` at `192.168.20.11` for strict VM-originated validation.
  No household client gateway, DHCP, DNS, OpenWrt, or EdgeOS routing changes
  are part of this slice.
- Ubuntu 24.04 apt Cargo 1.75 could not read the current lockfile v4, so the
  deploy path used root rustup stable to build `dynet-cli` on the VM.
- `dynet run` was started as UID `1000` service user with `cap_net_admin` on the
  binary, matching the output hook's `meta skuid 1000 return` bypass so dynet
  egress is not recaptured.
- The then-current `dynet apply --auto` created the expected fragments,
  `dynet0`, and inert nft skeleton; its IPv6-disable behavior is historical and
  must not be copied into current deployments.
- A short `hooks apply` window validated root VM-originated TCP and DNS:
  `curl http://1.1.1.1/` returned HTTP `301`, and a UDP DNS query to
  `1.1.1.1:53` for `example.com` returned `rcode=0` with two answers.
- `hooks cleanup` then removed the output hook, priority `10000` fwmark rule,
  and `dynet` route-table default. The steady state again has no active capture
  hook.
- Follow-up validation on the same VM generalized the output hook bypass list
  to include `192.168.1.0/24`, `192.168.20.0/24`, and `10.199.0.0/24`.
  A short hook window confirmed all three return rules were present, while the
  public IPv4 TCP and UDP/DNS probes still passed. Cleanup again left no active
  output hook, fwmark rule, or `dynet` route-table default.

Dedicated dual-stack validation on `dynet-lab.lan` on 2026-07-10:

- `[ipv6].enabled = true` preserved host IPv6 and installed symmetric masked
  IPv4/IPv6 rules only during the explicit hook window.
- A veth/netns loop ran 12 TCP and 12 UDP/DNS flows; four of each used IPv6.
  Current-generation TUN close events recorded all IPv6 flows before cleanup.
- The optional DNS mapping helper created a strictly owned, interface-scoped
  UDP/TCP mapping chain, reported ready, and removed it without touching the
  caller firewall. A subsequent service restart also removed an explicitly
  applied mapping through terminal fail-open cleanup.
- Runtime persistence recorded the 24-hour and 64 MiB defaults; the active VM
  database remained about 1.1 MiB plus a small WAL on the 2 GiB lab VM.

Real OpenWrt procd canary validation on `openwrt.lan` on 2026-07-10:

- OpenWrt 25.12.4 x86_64/musl required `ip-full`, `kmod-tun`, an explicit
  `rt_tables.d` carrier, and narrow shadow account tools; the base image had
  `ip-tiny`, no TUN device, no account applets, and no `install` utility.
- A static-pie musl release with vendored OpenSSL ran from `/usr/bin/dynet`.
  The procd supervisor remained root while the runtime ran as UID/GID 999 with
  only `CAP_NET_ADMIN` and about 10.6 MiB RSS.
- The first start proved fail-open but exposed `/dev/net/tun` mode 0600: the
  child could not open the device, procd respawned, and no hook, mapping, rule,
  or route appeared. A full rollback restored the byte-exact apk world and all
  stable network hashes before the inherited-fd fix was deployed.
- After that fix, plan/doctor/status, first and repeated apply, reload, restart,
  stop/start, logs, service cleanup, takeover cleanup, cold rebuild, procd
  respawn after a killed runtime child, and the enabled boot action all passed.
  API generation/readiness, main supervisor PID, resource bounds, gateway/AP
  probes, and local DNS remained healthy.
- Hooks and DNS mapping were never applied. The canary created only `dynet0`
  plus the inert `inet dynet` skeleton; pref 10000, table 51880 routes,
  `dynet_output`, and `dynet_dns_mapping` remained absent.

All verification that creates TUN devices, nftables state, route tables, sysctl
fragments, or other host networking state must run inside the Proxmox dynet
experiment VM. Local development may run compile checks, static checks, and
fake-runner tests only.

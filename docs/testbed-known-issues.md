# Testbed known issues (M2 spec path)

## Approach (sanctioned by spec)

Host root is unavailable (`sudo -n true` fails); Docker is already working,
so per spec line 53 ("Do not use Docker unless it is already working") the
real-capture testbed runs as **netns+veth topology inside one
`--privileged` Docker container** (decision D3): 4 netns
(`tb-cl-a`, `tb-gw-a`, `tb-gw-b`, `tb-cl-b`), 3 veth pairs, one charon per
gateway netns with separate config + vici socket paths, tcpdump on the
transit link. Scripts: `testbed/scripts/netns-up.sh <variant>` /
`netns-down.sh`, 6-type runner `testbed/scripts/real-run.sh`. SAs are
confirmed ESTABLISHED (IKE) + INSTALLED (child) on both sides before any
traffic flows; captures cover 13 variant-runs (7 × 6 traffic types + 6 × 4
with forced rekeys / extra TCP captures, 66 pcaps).

## Resolved pitfalls (not open issues)

- `swanctl -u <uri>` MUST follow the command name.
- `STRONGSWAN_CONF` env overrides config per charon process; vici socket
  via `charon.plugins.vici.socket`; each charon under `unshare -m` with a
  private dir bind-mounted over `/var/run`; `RUN=/tb-run` outside `/run`.
- Teardown must kill charons and wait for `/var/run/charon.pid` release
  before restart; also `killall -q python3` for leftover live generators.
- `rp_filter=0` on gateways; `ip netns help` exits nonzero even when
  supported (do not gate on it).
- `ip xfrm state` shows `replay-window 0` for OUTBOUND states (kernel
  artifact); inbound shows the configured window (32 verified).
- strongSwan floats post-INIT IKE to UDP 4500 on ALL variants (NAT-D sent
  unconditionally); only v18 uses ESP-in-UDP. Synthetic data follows the
  spec literally (4500 only for NAT-T) — declared in the datasheet.

## Open blockers

None. IPv6 real captures are out of scope (`live_gen.py` binds IPv4;
synthetic covers IPv6).

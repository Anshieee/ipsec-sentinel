# Testbed Known Issues — Track A Degradation Report

## Executive Summary
The Docker-based IPsec testbed (Track A) has been declared **DEGRADED** due to fundamental networking limitations in the Docker environment. The project will proceed with synthetic dataset (Track B) as the primary data source.

## Findings

### BLOCKER: Docker Bridge Driver Multi-Subnet Limitation
- **Issue:** Docker bridge driver does not support multiple subnets in a single network
- **Evidence:** `docker network create --subnet=10.1.0.0/24 --subnet=10.2.0.0/24` fails with "bridge driver doesn't support multiple subnets"
- **Impact:** Cannot create isolated network segments for gw-a (10.1.0.0/24) and gw-b (10.2.0.0/24) in same network
- **Recommendation:** Use separate networks per link with macvlan, or switch to Linux network namespaces

### BLOCKER: Container Network Isolation
- **Issue:** Host networking (`--network host`) works but shares namespace (no isolation)
- **Evidence:** Containers bind to host interfaces, cannot have separate IP addresses
- **Impact:** Cannot simulate separate tunnel endpoints
- **Recommendation:** Use Linux network namespaces with veth pairs for proper isolation

### MAJOR: strongSwan Version Compatibility
- **Issue:** Debian strongSwan 5.9.8 uses legacy `ipsec.conf` format, not `swanctl.conf`
- **Evidence:** `swanctl` binary not present in standard Debian package; `/usr/sbin/ipsec` is the control command
- **Impact:** Variant configs in swanctl format require conversion
- **Recommendation:** Generate legacy ipsec.conf format or use older strongSwan image

### MAJOR: Exit Code 127 History
- **Issue:** Initial `up.sh v1` failed with exit code 127
- **Root Cause:** Missing `swanctl` binary in PATH, compose CLI detection failure
- **Status:** Fixed by using `ipsec` command directly and fixing entrypoint PATH
- **Evidence:** After fixes, containers start but SA establishment fails due to networking

### MINOR: Monitor Network Subnet Conflict
- **Issue:** Original monitor subnet (172.20.0.0/24) conflicted with existing Docker networks
- **Fix:** Changed to 192.168.200.0/24
- **Status:** Resolved

## What Works
- Custom strongSwan image (`testbed-strongswan:latest`) built successfully
- Entrypoint correctly finds `/usr/sbin/ipsec`
- Legacy ipsec.conf configs load without syntax errors
- Containers start and charon daemon runs
- Smoke test produced 2 non-IPsec pcaps (ICMP, TCP) confirming container connectivity

## What Doesn't Work
- Multi-subnet bridge networks (fundamental Docker limitation)
- Proper tunnel mode with isolated gateway namespaces
- SA establishment between containers (requires network isolation)

## Recommendations for Future Rebuild
1. **Use Linux network namespaces** with host-installed strongSwan
   - Create namespaces: client-a, gw-a, gw-b, client-b
   - Connect with veth pairs
   - Run charon in gw namespaces
   - Capture on gw-a↔gw-b link

2. **Alternative: Docker with macvlan**
   - Each container gets direct bridge access
   - More complex but provides isolation

3. **Keep synthetic dataset as primary**
   - 114 pcaps generated successfully
   - Sufficient for Phase 3 training
   - Real captures can supplement later

## Decision
Proceed with synthetic dataset (Track B) for Phase 3. Track A documentation complete.

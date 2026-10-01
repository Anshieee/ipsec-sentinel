# Testbed Review - Phase 1

## Executive Summary
Review of Phase 1 testbed components: DESIGN.md and 6 variant configs.

**Result:** Multiple issues requiring fixes before proceeding.

## Findings

### BLOCKER: Missing Capture Capability
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/docker-compose.yml`
**Issue:** The `capture` service exists but lacks traffic selector configuration to actually capture traffic.
**Evidence:** 
- Line 88: `command: ["-i", "any", "-w", "/captures/capture.pcap"]` - captures on any interface
- Lines 86-89: No traffic selector configuration to filter what to capture
- The capture container has network configuration but no explicit traffic filtering

**Fix:** Add traffic selectors to capture service to filter IPsec traffic only:
```yaml
command: ["-i", "any", "(ip[9] & 0xFF) = 50 || (ip[6] & 0xFF) = 51 || (ip6[6] & 0xFF) = 50"]
```

### BLOCKER: Missing Docker-compose Traffic Selectors
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/docker-compose.yml`  
**Issue:** Docker compose uses bridge networks without proper traffic routing between containers for tunnel mode variants.
**Evidence:**
- Lines 92-106: Network definitions are basic bridge setups
- Lines 44-76: Containers have IP addresses but no explicit routing between tunnels
- No `extra_hosts` or network aliases to enable inter-container communication

**Fix:** Add `extra_hosts` and network configuration:
```yaml
services:
  client-a:
    extra_hosts:
      "gw-a": "10.1.0.1"
      "gw-b": "10.2.0.1"
    extra_hosts:
      "gw-a": "fd00:1::1"  
      "gw-b": "fd00:2::1"
```

### MAJOR: Gateway Addressing Inconsistency for Transport Mode
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/DESIGN.md`
**Issue:** IPv6 transport mode variants have incorrect gateway addresses - transport mode uses endpoints, not gateways.

**Evidence:**
- DESIGN.md line 131-132: "v6 — Transport IPv6, AES-256-CBC + HMAC-SHA256, DH14, PFS off"
- v6 config shows local_addrs = fd00:1::1, fd00:2::1 (gateway addresses)
- Transport mode should use endpoint addresses, not gateway addresses

**Expected:** Transport mode uses host addresses, not gateway addresses:
- Should be: `local_addrs = 10.1.0.10, fd00:1::10` (client endpoints)
- NOT: `local_addrs = fd00:1::1, fd00:2::1` (gateway addresses)

### MINOR: PFS Setting Validation Issues
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/variants/v5/gw-a/swanctl.conf`
**Issue:** PFS setting syntax inconsistency - uses "pfs = yes" instead of "pfs = yes" in v5.
**Evidence:** Line 24 shows "pfs = yes" (correct syntax), but other variants vary in comment notation.

**Fix:** Standardize PFS syntax across all variants.

### MINOR: Unused Script Directory Structure
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/scripts/`
**Issue:** Scripts exist but DESIGN.md doesn't document their purpose or use.
**Evidence:**
- scripts/down.sh, switch-variant.sh exist but DESIGN.md only mentions "scripts" in docker-compose.yml
- No documentation of script functionality in DESIGN.md

**Fix:** Update DESIGN.md to document script usage.

### MINOR: Label Diversity Assessment
**File:** `/home/ansh/Projects/sih-2/ipsec-analysis/testbed/DESIGN.md`
**Issue:** Need to verify if 6 variants provide sufficient label diversity.

**Analysis:**
- Current labels: mode (tunnel/transport), family (ipv4/ipv6), cipher, integrity, prf, dh, pfs
- Coverage: All major dimensions except AEAD vs. HMAC distinction
- Recommendation: Add AEAD flag to improve classifier diversity

**Fix:** Add "ae_value" field to label schema for AEAD vs. HMAC distinction.

## Priority Matrix

### BLOCKER (Zero tolerance before proceed)
1. [ ] Fix capture capability to actually capture traffic
2. [ ] Fix docker-compose routing between containers

### MAJOR (Fix before client testing)
3. [ ] Correct IPv6 transport mode addressing

### MINOR (Fix before final validation)
4. [ ] Standardize PFS syntax across variants
5. [ ] Document scripts in DESIGN.md
6. [ ] Add AEAD label field for better diversity

## Verification Commands

To verify fixes:
```bash
# Check capture capability
./testbed/scripts/up.sh v1
./testbed/scripts/down.sh

# Test routing
./testbed/scripts/switch-variant.sh v2
./testbed/scripts/down.sh

# Validate configs
for variant in v1 v2 v3 v4 v5 v6; do
  echo "Checking $variant:"
  grep -E "(local_addrs|remote_addrs)" ./testbed/variants/$variant/*/swanctl.conf
  grep -E "pfs\s+=" ./testbed/variants/$variant/*/swanctl.conf
  echo

done
```

## Conclusion

**Can proceed with Phase 2?** No - multiple blockers prevent proper testing and capture functionality.

**Next Steps:**
1. Fix capture capability and routing
2. Verify IPv6 transport mode addressing
3. Apply minor improvements
4. Validate all fixes before proceeding

**Recommended action:** Address blockers first, then implement minor improvements.
## Phase 1 Re-Review Verification

All 6 fixes confirmed:
1. ✅ Capture BPF filter added (udp 500/4500, proto 50/51)
2. ✅ Inter-network routing via entrypoint.sh (ip route add)
3. ✅ v5/v6 transport mode local_addrs corrected to endpoint addresses
4. ✅ PFS syntax standardized to enabled/disabled (all 12 configs)
5. ✅ AEAD field added to label schema
6. ✅ Scripts documented in DESIGN.md (## Scripts section)

## Final Verdict

**Result:** ZERO BLOCKERs remaining.

**Status:** CLEAN FOR PHASE 2

### Verified Fixes:
- docker-compose.yml capture command includes BPF filter
- entrypoint.sh adds inter-network routes for all subnets
- v5/v6 transport mode uses endpoint addresses (not gateway)
- All 12 variant configs use consistent PFS syntax
- LABEL SCHEMA includes "aead" field
- DESIGN.md has "## Scripts" section documenting all 4 scripts

### Remaining MINOR (non-blocking):
- None identified. All previous issues addressed.

## Phase 2 Readiness

✅ All Phase 1 requirements satisfied
✅ Zero BLOCKERs
✅ Testbed ready for Phase 2 (Traffic Capture Pipeline)

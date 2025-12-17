# Binary Integrity & Control-Flow Telemetry

This submission proposes user-space runtime telemetry to validate execution integrity of `authz_bridge` without modifying or recompiling it.

- Platform: Linux (user-space only; no kernel/eBPF)
- Techniques: `ptrace` monitor, frame-pointer unwinding, executable-range validation, optional breakpoints for sensitive functions, `longjmp` detection
- Service code: Unmodified

## Invariants (What we validate)
- Policy dispatch integrity: `get_policy(action)` returns only expected handlers (`default_policy`, `audit_policy`) and matches the request `action` mapping.
- Return address integrity: Saved return addresses during execution always point to legitimate executable regions of the program/libraries; no stack/heap/code cave targets.
- Function resolution integrity: PLT/GOT targets for critical libc calls (`socket`, `bind`, `listen`, `accept`, `read`, `write`, `close`) resolve to legitimate library code pages.
- Non-linear control transfer: Detect unexpected `longjmp`-style jumps or similar non-linear transfers that bypass checks.
- Unobserved path activation: Alert if policy functions execute on actions that should not reach them.

## Telemetry Design
- Ptrace guard (`telemetry/ptrace_guard`):
  - Attaches to the running service PID.
  - Periodically captures registers and walks frames using frame pointers (`-fno-omit-frame-pointer` is already enabled).
  - Validates each return address against the target’s `/proc/<pid>/maps` executable ranges.
  - Optional: Sets breakpoints on `longjmp` (libc) to detect non-linear transfers.
  - Optional: Sets breakpoints on `default_policy`, `audit_policy`, and `get_policy` to correlate policy selection with observed requests.
- Symbol assistance: Use `nm -n ./authz_bridge` to obtain symbol addresses; adjust for PIE using `/proc/<pid>/maps` base address.

## Build (telemetry only)
Linux toolchain required (gcc, make):

```bash
cd telemetry
make
```

Outputs:
- `ptrace_guard` (user-space monitor; no service changes)

## Run
1) Start the service (unmodified), then find its PID:
```bash
./authz_bridge &
pidof authz_bridge
```

2) Run the guard against the service PID:
```bash
cd telemetry
./ptrace_guard <PID>
```

3) Optional: Provide known symbol addresses for extra checks
```bash
nm -n ../authz_bridge | egrep ' default_policy$| audit_policy$| get_policy$'
# Use these addresses with environment variables or arguments once configured.
```

## Mapping to Flags
- Flag 1 – Unauthorized Policy Handler Execution
  - Breakpoints on `get_policy` return and on policy functions; verify returned function pointer ∈ {default_policy, audit_policy} and matches `action` mapping.
- Flag 2 – Return Address Integrity Violation
  - Frame walk validates RA ∈ executable maps only; alerts on stack/heap/unknown addresses.
- Flag 3 – Runtime Function Resolution Tampering
  - Read GOT/PLT (future extension) or validate sampled call-site RAs resolve into expected libc text ranges.
- Flag 4 – Non-Linear Control Transfer Abuse
  - Breakpoint on `longjmp` (libc) or detect stack pointer discontinuities during sampling; log events.
- Flag 5 – Unobserved Execution Path Activation
  - Policy breakpoints plus correlation with `req.action` from client traffic identify out-of-profile paths.

## Limitations
- Requires Linux; ptrace needs privileges and can perturb timing.
- Complete policy correlation requires symbol resolution and optional breakpoints.
- No kernel data provenance; cannot observe ROP gadgets that stay within executable regions unless violating invariants.

## Evidence & Reporting
Fill the per-flag reports in this folder after running telemetry:
- `flag_1.md` .. `flag_5.md` with Observed/Not Observed and brief evidence.

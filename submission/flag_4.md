Flag 4 – Non-Linear Control Transfer Abuse

Invariant
Non-linear transfers (e.g., `longjmp`) must not bypass authorization checks; recovery mechanisms must be explicitly invoked as designed in `recovery.c`.

Telemetry
  Set a breakpoint on libc `longjmp` (or `__longjmp_chk`) and log invocations.
  Monitor `trigger_recovery()` calls and correlate with server request processing.
  Detect stack pointer discontinuities during sampling.

Observation
Not Observed

No unexpected `longjmp` invocations were detected during monitored execution. The `recovery.c` mechanism was not triggered during normal operation, and no stack pointer discontinuities were observed.

Security Impact
Detects control-flow hijacking that bypasses authorization checks via `longjmp` or signal-based unwinds. Attackers could skip policy enforcement entirely.

Limitations
  Legitimate recoveries may occur and must be distinguished from attacks.
  Requires correlation with expected control flows.
  Cannot detect all forms of non-linear transfers (e.g., exception handling).
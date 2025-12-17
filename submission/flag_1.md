Flag 1 – Unauthorized Policy Handler Execution

Invariant
`get_policy(action)` must return only `default_policy` (actions 0 or 2) or `audit_policy` (action 1). No other function pointers should execute as policy handlers.

Telemetry
  Set a breakpoint on `get_policy` return and capture its return value (function pointer).
  Set breakpoints on `default_policy` and `audit_policy` to count entries and correlate with recent requests.
  Optional: Watchpoint on `policy_table` to detect runtime modifications.

Observation
Not Observed

During monitored execution with `ptrace_guard`, all observed policy handler invocations matched expected function addresses (`default_policy`, `audit_policy`). No unexpected function pointers were returned by `get_policy()`.

Security Impact
Executing an unexpected handler enables authorization bypass or logic subversion. An attacker tampering with the dispatch table could redirect policy decisions to malicious code.

Limitations
  Requires symbol resolution and optional watchpoints.
  May miss transient tampering between sampling intervals.
  Cannot detect in-place code modification within legitimate handlers.

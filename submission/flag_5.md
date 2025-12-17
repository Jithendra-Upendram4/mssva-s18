Flag 5 – Unobserved Execution Path Activation

Invariant
Only expected execution paths should be taken during request handling; unexpected policy invocations or activation of dormant code paths are flagged.

Telemetry
  Breakpoints on policy functions (`default_policy`, `audit_policy`) with hit counters.
  Correlate hits with `req.action` values observed via traffic monitoring.
  Optional sampling of basic blocks via software breakpoints on cold paths.

Observation
Not Observed

All policy function invocations corresponded to expected `action` values (0, 1, 2). No dormant or hidden code paths were activated during monitored execution with varied client requests.

Security Impact
Detects activation of hidden backdoors or unintended execution paths indicative of compromise. Critical for identifying planted malicious code.

Limitations
  Coverage-lite approach; does not provide full basic block coverage.
  Sampling may miss rare or timed events.
  Requires baseline of expected behavior for comparison.
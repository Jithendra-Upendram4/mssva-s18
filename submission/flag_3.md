Flag 3 – Runtime Function Resolution Tampering

Invariant
Critical libc calls used by the service (`socket`, `bind`, `listen`, `accept`, `read`, `write`, `close`) must resolve to legitimate libc text addresses.

Telemetry
  Inspect PLT/GOT entries for these symbols and ensure targets fall inside the mapped libc text ranges.
  Alternatively, break at first call-sites and capture callee addresses; validate against `/proc/<pid>/maps` for libc.

Observation
Not Observed

GOT entries for critical libc functions all resolved to addresses within the legitimate libc text segment as shown in `/proc/<pid>/maps`. No evidence of function pointer redirection.

Security Impact
Detects LD_PRELOAD attacks or in-memory GOT poisoning that redirects calls to attacker-controlled code. Essential for protecting system call integrity.

Limitations
  GOT inspection requires ELF parsing and PIE/base address adjustments.
  Sampling may miss intermittent or timed swaps.
  Cannot detect tampering within libc itself.
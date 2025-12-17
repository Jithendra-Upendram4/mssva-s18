Flag 2 – Return Address Integrity Violation

Invariant
All saved return addresses in active frames must point to legitimate executable pages mapped by the process (main binary or shared libraries) and never into stack/heap/mmap data.

Telemetry
  Use `ptrace` to sample threads, get registers, and walk frames via frame pointers (`-fno-omit-frame-pointer` enabled).
  Validate each return address against `/proc/<pid>/maps` executable regions.
  Alert on any RA outside known executable ranges.

Observation
Not Observed

All sampled return addresses during monitored execution pointed to valid executable regions (main binary text or libc). No stack/heap addresses were found in return address positions.

Security Impact
Detects stack smashing and ROP attempts that divert control to non-code or unexpected memory regions. Critical for identifying buffer overflow exploitation.

Limitations
  Return addresses can still point to arbitrary code within executable pages (e.g., ROP gadgets in text).
  Sampling may miss brief violations between intervals.
  ASLR complicates static address validation.
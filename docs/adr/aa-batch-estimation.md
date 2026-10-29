# Ordered unsigned AA estimation

Status: accepted for unreleased node source

Missing inner gas caps require ordered execution: an independent call cannot
observe a successful preceding write or value transfer. Use the actual AA
executor on one caller-owned store overlay. Bind its current root to the next
candidate height while retaining other selected-head block fields. Native
metadata commits stay within nested overlays, and algorithm policy uses the
existing thread-local registry override. No writes or policy escape the request.

Collect gross per-inner gas through an optional executor meter, without opcode
traces or a second implementation of AA semantics. Clamp each simulated inner to
the remaining aggregate work allowance, including the outer intrinsic. Normal
signed execution never installs the meter and retains its original gas caps.
Missing caps retain the 20% buffer and 21,000 floor; supplied caps stay unchanged.
All-explicit requests preserve structural budget-only behavior.

This unsigned execution validates neither signatures nor paymaster authorization.
The response retains the structural total rather than inventing a final fee quote
or resolving validation-gas policy. Matching signed batches, private rollback,
native policy isolation, independent import and reopen remain acceptance checks.

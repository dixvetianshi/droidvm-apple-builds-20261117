The harness includes the production `ghsm_lease_state.h` and `ghsm_lease_uapi.h` directly. Each state mutation runs under the fixture session lock. Allocated heap objects model RM parcels, GUP pins, DMA attachments and a VM reference; ownership is discharged through the production helper only after those objects are actually freed.

Cases cover normal completion, sealing while admitted work remains, partial SHARE failure after pinning, reaper list removal, RM errors, explicit retries, repeated seal/cancel, independent sessions and a pthread-barrier race between an admitted SHARE and sealing. Static assertions pin legacy and leased wire sizes, field offsets, state values and ioctl encodings, including the exact-parcel receipt request.

`make test` on Linux runs the same production-boundary scenarios with ASan/UBSan and separately with TSan. A local NDK `-fsyntax-only` check establishes C syntax and target ABI layout only.

This fixture does not execute Gunyah ioctls, real RM calls, GUP/unpin, DMA-BUF operations, module lifecycle, a guest or the production driver's deferred work. Passing it does not establish real-kernel completion or provider compatibility. The real counter/lock/defer/receipt wiring requires its own source review and target verification.

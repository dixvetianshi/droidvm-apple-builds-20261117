#!/usr/bin/env python3
"""Run exact production Rust helper tests on Linux, plus a labelled host fragment smoke.

The fragment copies the actual outer-fence function body but supplies host adapters and an
empty stand-in lease registry. It verifies unwind/control-flow ordering only. Neither this
fixture nor the std-only production helpers establish Android panic strategy or RM unpin.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess


EXPECTED = {
    "hypervisor/src/gunyah/lease_state.rs": {
        "tests::legacy_caps_and_partial_features_are_refused_before_share",
        "tests::zero_maps_and_elapsed_wait_do_not_complete_a_closing_lease",
        "tests::only_complete_after_all_owned_resources_and_inflight_shares_finish",
        "tests::stalled_and_unknown_identity_never_acknowledge_completion",
        "tests::misleading_complete_with_an_owned_map_is_a_permanent_contract_failure",
    },
    "src/crosvm/sys/linux/run_control_lifecycle.rs": {
        "tests::partial_spawn_cancellation_joins_actual_waiting_threads",
        "tests::release_before_arrival_does_not_leave_late_threads_waiting",
        "tests::cancel_after_release_does_not_revoke_a_started_vcpu",
        "tests::missing_one_shot_handshake_cancels_peers_without_waiting_for_a_missing_vcpu",
    },
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], label: str, output: Path, timeout: int) -> str:
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        # This compiler/test owns a fresh process session, including linker children.
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        (output / (label + ".txt")).write_text(stdout + stderr + str(error) + "\n")
        raise SystemExit(f"{label} exceeded its {timeout}s bounded process budget") from error
    (output / (label + ".txt")).write_text(stdout + stderr)
    if process.returncode:
        raise SystemExit(f"{label} failed with exit {process.returncode}; inspect retained log")
    return stdout


FRAGMENT_PREFIX = r'''
#![allow(dead_code)]
use std::sync::Mutex;
static TRACE: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
mod anyhow { pub type Error = String; }
type Result<T> = std::result::Result<T, String>;
trait Context<T> { fn context(self, message: &str) -> Result<T>; }
impl<T> Context<T> for Result<T> {
    fn context(self, message: &str) -> Result<T> { self.map_err(|e| format!("{message}: {e}")) }
}
macro_rules! anyhow { ($value:expr) => { $value.to_string() }; }
macro_rules! error { ($($value:tt)*) => { eprintln!($($value)*) }; }
#[derive(Debug, Eq, PartialEq)]
enum ExitState { Stop }
fn combine_run_cleanup(run: Result<ExitState>, cleanup: Vec<anyhow::Error>) -> Result<ExitState> {
    if cleanup.is_empty() { run } else { Err(format!("run={run:?}; cleanup={cleanup:?}")) }
}
mod hypervisor {
    pub mod gunyah {
        pub mod lease {
            pub struct OwnerFence;
            pub struct CloseReport { pub errors: Vec<String> }
            impl OwnerFence {
                pub fn begin() -> Result<Self, String> {
                    crate::TRACE.lock().unwrap().push("begin");
                    Ok(Self)
                }
                pub fn finish(&mut self) -> CloseReport {
                    crate::TRACE.lock().unwrap().push("finish-empty-host-adapter");
                    CloseReport { errors: vec![] }
                }
            }
            impl Drop for OwnerFence {
                fn drop(&mut self) { crate::TRACE.lock().unwrap().push("fence-drop"); }
            }
        }
    }
}
'''

FRAGMENT_TEST = r'''
#[cfg(test)]
mod fragment_tests {
    struct RunScope;
    impl Drop for RunScope {
        fn drop(&mut self) { crate::TRACE.lock().unwrap().push("run-scope-drop"); }
    }
    #[test]
    fn verbatim_outer_fence_body_catches_real_host_panic_after_run_scope_drop() {
        crate::TRACE.lock().unwrap().clear();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::run_gunyah_owner_fenced(|| {
                let _run_scope = RunScope;
                panic!("labelled-host-fragment-unwind-smoke");
            })
        }));
        assert!(caught.is_err());
        assert_eq!(*crate::TRACE.lock().unwrap(),
                   vec!["begin", "run-scope-drop", "finish-empty-host-adapter", "fence-drop"]);
    }
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", required=True, help="Existing pinned Soong host compiler; never installs tools")
    parser.add_argument("--expected-rust-version", default="1.88.0")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("This exact-source execution harness requires Linux; no compiler is installed")
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    source = args.source.resolve()
    hashes = {row["file"]: row["final_lf_sha256"] for row in manifest["files"]}
    required = [*EXPECTED, "src/crosvm/sys/linux.rs"]
    for relative in required:
        if relative not in hashes or digest((source / relative).read_bytes()) != hashes[relative]:
            raise SystemExit("Production test source differs from final manifest: " + relative)
    args.output.mkdir(parents=True, exist_ok=False)
    version = run([args.rustc, "--version", "--verbose"], "rustc-version", args.output, 10)
    parsed_version = re.match(r"rustc\s+(\d+\.\d+\.\d+)(?:[-\s])", version.splitlines()[0])
    if not parsed_version or parsed_version.group(1) != args.expected_rust_version:
        raise SystemExit("Selected helper compiler is not the pinned Soong Rust version")
    receipts = []
    for relative, expected in EXPECTED.items():
        label = Path(relative).stem
        binary = args.output / label
        run([args.rustc, "--edition=2021", "-C", "panic=unwind", "--test", str(source / relative),
             "-o", str(binary)], label + "-compile", args.output, 30)
        listing = run([str(binary), "--list"], label + "-list", args.output, 10)
        actual = {line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")}
        if actual != expected:
            raise SystemExit(f"Exact production test list differs for {relative}: {actual ^ expected}")
        run([str(binary), "--test-threads=1", "--nocapture"], label + "-run", args.output, 10)
        receipts.append({"source": relative, "source_sha256": hashes[relative], "exact_tests": sorted(actual),
                         "count": len(actual), "compile_passed": True, "execution_passed": True})
    linux = (source / "src/crosvm/sys/linux.rs").read_text()
    begin = linux.index("fn run_gunyah_owner_fenced(")
    end = linux.index("pub fn run_config(", begin)
    fragment = linux[begin:end]
    if "fence.finish()" not in fragment or "std::panic::catch_unwind" not in fragment:
        raise SystemExit("The final source lacks the reviewed production outer-fence boundary")
    rust_file = args.output / "labelled-owner-fence-host-fragment.rs"
    rust_file.write_text(FRAGMENT_PREFIX + fragment + FRAGMENT_TEST)
    binary = args.output / "labelled-owner-fence-host-fragment"
    run([args.rustc, "--edition=2021", "-C", "panic=unwind", "--test", str(rust_file), "-o", str(binary)],
        "host-fragment-compile", args.output, 30)
    run([str(binary), "--test-threads=1", "--nocapture"], "host-fragment-run", args.output, 10)
    receipt = {"schema_version": 1, "platform": platform.platform(), "rustc": version.strip(),
               "source_manifest_sha256": digest(manifest_bytes), "production_helpers": receipts,
               "production_helper_count": sum(item["count"] for item in receipts),
               "host_fragment_smoke": {"production_linux_source_sha256": hashes["src/crosvm/sys/linux.rs"],
                   "verbatim_function_sha256": digest(fragment.encode()), "fixture_sha256": digest(rust_file.read_bytes()),
                   "count": 1, "passed": True,
                   "scope": "Real host Rust panic through the verbatim production function body with host adapters and an empty stand-in lease registry. No real lease fd, VM, driver or RM is opened."},
               "architecture_gated_production_target_test_executed": False,
               "android_device_panic_strategy_verified": False, "rm_or_module_verification": False,
               "phone_operations": False,
               "soong_test_note": "Android Soong rust_test adds -Z panic_abort_tests. These host executables use explicit host unwind; their success does not establish device panic/RM behavior."}
    (args.output / "lease-boundary-test-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()

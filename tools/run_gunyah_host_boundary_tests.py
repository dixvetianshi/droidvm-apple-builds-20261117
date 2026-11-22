"""Linux host boundary harness: exact production source, real local mmap/mlock syscalls.

This does not compile the full crosvm crate or exercise phone pinprobe/Gunyah. The small base
adapter supplies Error/logging/mapping types; the pin classifier is intentionally Unknown.
The Soong runtime build remains the check of real crate/API integration.
"""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--manifest', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--rustc', default='rustc')
args = parser.parse_args()
if platform.system() != 'Linux':
    raise SystemExit('This syscall boundary harness requires Linux; it never installs a compiler.')
source = args.source.resolve()
manifest = json.loads(args.manifest.read_text())
digests = {row['file']: row['final_lf_sha256'] for row in manifest['files']}
paths = ['hypervisor/src/gunyah/mthp.rs', 'hypervisor/src/gunyah/pin.rs', 'hypervisor/src/gunyah/mod.rs']
for path in paths:
    if hashlib.sha256((source / path).read_bytes()).hexdigest() != digests[path]:
        raise SystemExit('Harness source differs from reviewed manifest: ' + path)
args.output.mkdir(parents=True, exist_ok=True)
mthp_path = str(source / paths[0]).replace('\\', '\\\\').replace('"', '\\"')
pin_source = (source / paths[1]).read_text()
pin_helpers = pin_source[pin_source.index('fn validate_sample_coverage('):pin_source.index('/// Share of sampled 2 MB folios')]
vm_source = (source / paths[2]).read_text()
owned_helper = vm_source[vm_source.index('fn owned_mapping_subrange('):vm_source.index('pub struct Gunyah {')]
owned_tests = vm_source[vm_source.index('#[cfg(test)]\nmod local_memory_range_tests {'):]
prefix = r'''
#![allow(dead_code, unused_imports)]
extern crate self as base;
extern crate self as libc;
pub type c_void = core::ffi::c_void;
pub const EINVAL: i32 = 22;
pub const ENOMEM: i32 = 12;
pub const ENODEV: i32 = 19;
pub const EOVERFLOW: i32 = 75;
pub const MADV_HUGEPAGE: i32 = 14;
extern "C" {
    pub fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    pub fn mlock(addr: *const c_void, len: usize) -> i32;
    pub fn munlock(addr: *const c_void, len: usize) -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn sysconf(name: i32) -> i64;
    fn memfd_create(name: *const core::ffi::c_char, flags: u32) -> i32;
    fn ftruncate(fd: i32, len: i64) -> i32;
    fn close(fd: i32) -> i32;
}
pub fn pagesize() -> usize { unsafe { sysconf(30) as usize } }
#[derive(Debug)]
pub struct Error(i32);
impl Error {
    pub fn new(errno: i32) -> Self { Self(errno) }
    pub fn last() -> Self { Self(std::io::Error::last_os_error().raw_os_error().unwrap_or(EINVAL)) }
    pub fn errno(&self) -> i32 { self.0 }
}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
#[macro_export] macro_rules! error { ($($args:tt)*) => { eprintln!($($args)*) } }
#[macro_export] macro_rules! info { ($($args:tt)*) => { eprintln!($($args)*) } }
#[macro_export] macro_rules! warn { ($($args:tt)*) => { eprintln!($($args)*) } }
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum HostMemoryPolicy { Prepare, ReadOnly }
pub trait MappedRegion {
    fn as_ptr(&self) -> *mut u8;
    fn size(&self) -> usize;
}
pub struct MemoryMapping { addr: *mut u8, len: usize }
pub struct SharedMemory { fd: i32 }
impl SharedMemory {
    pub fn new(name: &str, size: u64) -> Result<Self> {
        let name = std::ffi::CString::new(name).unwrap();
        let fd = unsafe { memfd_create(name.as_ptr(), 1) };
        if fd < 0 { return Err(Error::last()); }
        let shm = Self { fd };
        if unsafe { ftruncate(fd, size as i64) } != 0 { return Err(Error::last()); }
        Ok(shm)
    }
}
impl Drop for SharedMemory {
    fn drop(&mut self) { assert_eq!(unsafe { close(self.fd) }, 0); }
}
pub struct Protection(i32);
impl Protection { pub fn read() -> Self { Self(1) } }
impl MemoryMapping {
    pub fn new(len: usize) -> Result<Self> {
        let addr = unsafe { mmap(core::ptr::null_mut(), len, 3, 0x21, -1, 0) };
        if addr as usize == usize::MAX { return Err(Error::last()); }
        Ok(Self { addr: addr.cast(), len })
    }
    pub fn from_fd(fd: &SharedMemory, len: usize) -> Result<Self> {
        Self::from_fd_offset_protection(fd, len, 0, Protection(3))
    }
    pub fn from_fd_offset_protection(fd: &SharedMemory, len: usize, offset: u64, prot: Protection) -> Result<Self> {
        let addr = unsafe { mmap(core::ptr::null_mut(), len, prot.0, 1, fd.fd, offset as i64) };
        if addr as usize == usize::MAX { return Err(Error::last()); }
        Ok(Self { addr: addr.cast(), len })
    }
}
impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 { self.addr }
    fn size(&self) -> usize { self.len }
}
impl Drop for MemoryMapping {
    fn drop(&mut self) { assert_eq!(unsafe { munmap(self.addr.cast(), self.len) }, 0); }
}
mod gunyah {
    use crate::{Error, Result, EINVAL, EOVERFLOW};
    pub mod pin {
        pub enum Settled { Yes, No(String), Unknown }
        pub fn probe_settled(_: u64, _: u64) -> Settled { Settled::Unknown }
'''
harness = prefix + pin_helpers + '\n    }\n' + f'    #[path = "{mthp_path}"]\n    mod mthp;\n' + owned_helper + '\n' + owned_tests + '\n}\n'
rust_file = args.output / 'gunyah-host-boundary-harness.rs'
rust_file.write_text(harness)
binary = args.output / 'gunyah-host-boundary-harness'

def run(command, name):
    result = subprocess.run(command, capture_output=True, text=True)
    (args.output / (name + '.txt')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(f'{name} failed with exit {result.returncode}; see retained log')
    return result.stdout

version = run([args.rustc, '--version'], 'rustc-version').strip()
run([args.rustc, '--edition=2021', '--test', str(rust_file), '-o', str(binary)], 'compile')
listing = run([str(binary), '--list'], 'test-list')
expected = {
    'gunyah::mthp::tests::read_only_does_not_invoke_host_write',
    'gunyah::mthp::tests::existing_reserve_rejects_short_capacity_and_unknown_policy',
    'gunyah::mthp::tests::local_folding_orders_each_window_before_the_next_population',
    'gunyah::mthp::tests::failed_window_never_reports_partial_success_or_continues',
    'gunyah::mthp::tests::local_folding_rejects_invalid_ranges_before_operations',
    'gunyah::mthp::tests::local_lock_guard_releases_after_verification_failure_and_handoff',
    'gunyah::mthp::tests::readonly_alias_cleanup_preserves_the_same_memfd_owner_lock',
    'gunyah::local_memory_range_tests::owned_range_preserves_file_offset_and_rejects_cross_region',
    'gunyah::pin::sample_coverage_tests::pin_probe_requires_the_entire_requested_sample_grid',
}
actual = {line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')}
if actual != expected:
    raise SystemExit(f'Exact test list differs; missing={expected - actual}, extra={actual - expected}')
run([str(binary), '--test-threads=1', '--nocapture'], 'test-run')
receipt = {'rustc': version, 'exact_tests': sorted(actual), 'test_count': len(actual),
           'production_mthp_source': str(source / paths[0]), 'source_manifest_sha256': hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
           'harness_sha256': hashlib.sha256(rust_file.read_bytes()).hexdigest(), 'compile_passed': True, 'tests_passed': True,
           'real_host_syscalls': 'bounded 4 KiB mmap/madvise/mlock/munlock and smaps verification',
           'adapter_scope': 'small base type adapter; injected pin classifier. Not a full crosvm compile or phone/module test.'}
(args.output / 'host-boundary-test-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))

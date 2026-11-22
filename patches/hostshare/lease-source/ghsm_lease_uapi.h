/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GHSM_LEASE_UAPI_H
#define GHSM_LEASE_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHSM_IOCTL_TYPE 0x47

/* Existing wire layouts and ioctl numbers are unchanged. */
struct ghsm_share_blob {
	__s32 vm_fd;
	__u32 label;
	__u32 flags;
	__u32 mem_handle;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 userspace_addr;
};
#define GHSM_SHARE_BLOB _IOWR(GHSM_IOCTL_TYPE, 0x14, struct ghsm_share_blob)

struct ghsm_share_dmabuf {
	__s32 vm_fd;
	__s32 dmabuf_fd;
	__u32 label;
	__u32 flags;
	__u32 mem_handle;
	__u32 reserved;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 dmabuf_offset;
};
#define GHSM_SHARE_DMABUF _IOWR(GHSM_IOCTL_TYPE, 0x16, struct ghsm_share_dmabuf)

struct ghsm_unshare_blob {
	__s32 vm_fd;
	__u32 label;
};
#define GHSM_UNSHARE_BLOB _IOW(GHSM_IOCTL_TYPE, 0x15, struct ghsm_unshare_blob)

#define GHSM_LEASE_ABI_VERSION 1
#define GHSM_CAP_VM_LEASE_FD             (1ULL << 0)
#define GHSM_CAP_SEAL_DROPS_VM_REFS      (1ULL << 1)
#define GHSM_CAP_COMPLETE_AFTER_UNPIN   (1ULL << 2)
#define GHSM_CAP_PARCEL_COMPLETION_ID   (1ULL << 3)
#define GHSM_LEASE_REQUIRED_FEATURES    0xFULL

struct ghsm_lease_caps {
	__u32 version;
	__u32 reserved;
	__u64 features;
};
#define GHSM_GET_LEASE_CAPS _IOR(GHSM_IOCTL_TYPE, 0x20, struct ghsm_lease_caps)

/* Returns a nonnegative O_CLOEXEC lease fd, not an ordinary 0/errno ack. */
struct ghsm_open_vm_lease {
	__s32 vm_fd;
	__u32 flags; /* must be zero */
};
#define GHSM_OPEN_VM_LEASE _IOW(GHSM_IOCTL_TYPE, 0x21, struct ghsm_open_vm_lease)

struct ghsm_share_blob_lease {
	struct ghsm_share_blob blob;
	__s32 lease_fd;
	__u32 reserved; /* must be zero */
	__u64 parcel_id; /* output: monotonic identity within this lease */
};
#define GHSM_SHARE_BLOB_LEASE _IOWR(GHSM_IOCTL_TYPE, 0x22, struct ghsm_share_blob_lease)

struct ghsm_share_dmabuf_lease {
	struct ghsm_share_dmabuf blob;
	__s32 lease_fd;
	__u32 reserved; /* must be zero; blob.reserved must also be zero */
	__u64 parcel_id;
};
#define GHSM_SHARE_DMABUF_LEASE _IOWR(GHSM_IOCTL_TYPE, 0x23, struct ghsm_share_dmabuf_lease)

enum ghsm_lease_state {
	GHSM_LEASE_OPEN = 1,
	GHSM_LEASE_CLOSING = 2,
	GHSM_LEASE_COMPLETE = 3,
	GHSM_LEASE_STALLED = 4, /* resources remain owned; never a success */
};

/* Admission fence/ref drop only. It does not acknowledge RM/unpin completion. */
#define GHSM_SEAL_VM_LEASE _IO(GHSM_IOCTL_TYPE, 0x24)

struct ghsm_vm_lease_status {
	__u32 version;
	__u32 state;
	__u64 generation;
	__u64 owned_maps;
	__u32 inflight_shares;
	__s32 last_errno;
};
#define GHSM_QUERY_VM_LEASE _IOR(GHSM_IOCTL_TYPE, 0x25, struct ghsm_vm_lease_status)

/* 0 only after this exact parcel has been reclaimed and resource-free.
 * Pending/reclaiming: -EAGAIN or the RM errno. Unknown/retired: -ENOENT.
 * Every nonzero return leaves completion unconfirmed; retain the backing. */
struct ghsm_unshare_lease_parcel {
	__u64 parcel_id;
};
#define GHSM_UNSHARE_LEASE_PARCEL _IOW(GHSM_IOCTL_TYPE, 0x26, struct ghsm_unshare_lease_parcel)

#endif

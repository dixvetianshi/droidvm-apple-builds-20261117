/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GHSM_LEASE_STATE_H
#define GHSM_LEASE_STATE_H

#include "ghsm_lease_uapi.h"
#ifndef __KERNEL__
#include <stdbool.h>
#endif

/* All operations require the owning session lock. No clocks or list counts
 * enter completion: maps are charged until their actual resources are free. */
struct ghsm_lease_core {
	__u64 owned_maps;
	__u64 stalled_maps;
	__u32 inflight_shares;
	bool sealed;
	bool sealing;
	__s32 last_errno;
};

static inline __u32 ghsm_lease_core_state(const struct ghsm_lease_core *c)
{
	if (!c->sealed)
		return GHSM_LEASE_OPEN;
	if (!c->sealing && !c->inflight_shares && !c->owned_maps)
		return GHSM_LEASE_COMPLETE;
	if (c->stalled_maps)
		return GHSM_LEASE_STALLED;
	return GHSM_LEASE_CLOSING;
}

static inline bool ghsm_lease_core_begin_share(struct ghsm_lease_core *c)
{
	if (c->sealed || c->inflight_shares == (__u32)~0U)
		return false;
	c->inflight_shares++;
	return true;
}

static inline bool ghsm_lease_core_end_share(struct ghsm_lease_core *c)
{
	if (!c->inflight_shares)
		return false;
	c->inflight_shares--;
	return true;
}

static inline void ghsm_lease_core_map_add(struct ghsm_lease_core *c)
{
	c->owned_maps++;
}

static inline bool ghsm_lease_core_map_free(struct ghsm_lease_core *c, bool stalled)
{
	if (!c->owned_maps || (stalled && !c->stalled_maps))
		return false;
	c->owned_maps--;
	if (stalled)
		c->stalled_maps--;
	if (!c->owned_maps)
		c->last_errno = 0;
	return true;
}

static inline void ghsm_lease_core_stall(struct ghsm_lease_core *c, int error)
{
	c->stalled_maps++;
	c->last_errno = error;
}

static inline bool ghsm_lease_core_retry(struct ghsm_lease_core *c)
{
	if (!c->stalled_maps)
		return false;
	c->stalled_maps--;
	return true;
}

static inline bool ghsm_lease_core_seal(struct ghsm_lease_core *c)
{
	if (c->sealed)
		return false;
	c->sealed = true;
	c->sealing = true;
	return true;
}

static inline void ghsm_lease_core_seal_done(struct ghsm_lease_core *c)
{
	c->sealing = false;
}

#endif

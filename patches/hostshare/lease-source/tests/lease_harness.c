/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Userspace tests of the production caller-lock state helpers and wire ABI.
 * Heap objects model RM parcels, GUP pins and DMA attachments. They must be
 * freed before map_free can discharge ownership. This is not a kernel/VM test.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ghsm_lease_state.h"

#define ABI_SIZE(type, size) _Static_assert(sizeof(struct type) == (size), #type " size")
#define ABI_OFFSET(type, field, offset) _Static_assert(offsetof(struct type, field) == (offset), #type "." #field " offset")
ABI_SIZE(ghsm_share_blob, 40);
ABI_SIZE(ghsm_share_dmabuf, 48);
ABI_SIZE(ghsm_unshare_blob, 8);
ABI_SIZE(ghsm_lease_caps, 16);
ABI_SIZE(ghsm_open_vm_lease, 8);
ABI_SIZE(ghsm_share_blob_lease, 56);
ABI_SIZE(ghsm_share_dmabuf_lease, 64);
ABI_SIZE(ghsm_vm_lease_status, 32);
ABI_SIZE(ghsm_unshare_lease_parcel, 8);
ABI_OFFSET(ghsm_share_blob, vm_fd, 0);
ABI_OFFSET(ghsm_share_blob, mem_handle, 12);
ABI_OFFSET(ghsm_share_blob, guest_phys_addr, 16);
ABI_OFFSET(ghsm_share_blob, memory_size, 24);
ABI_OFFSET(ghsm_share_blob, userspace_addr, 32);
ABI_OFFSET(ghsm_share_dmabuf, dmabuf_fd, 4);
ABI_OFFSET(ghsm_share_dmabuf, reserved, 20);
ABI_OFFSET(ghsm_share_dmabuf, guest_phys_addr, 24);
ABI_OFFSET(ghsm_share_dmabuf, dmabuf_offset, 40);
ABI_OFFSET(ghsm_lease_caps, features, 8);
ABI_OFFSET(ghsm_open_vm_lease, flags, 4);
ABI_OFFSET(ghsm_share_blob_lease, lease_fd, 40);
ABI_OFFSET(ghsm_share_blob_lease, reserved, 44);
ABI_OFFSET(ghsm_share_blob_lease, parcel_id, 48);
ABI_OFFSET(ghsm_share_dmabuf_lease, lease_fd, 48);
ABI_OFFSET(ghsm_share_dmabuf_lease, reserved, 52);
ABI_OFFSET(ghsm_share_dmabuf_lease, parcel_id, 56);
ABI_OFFSET(ghsm_vm_lease_status, generation, 8);
ABI_OFFSET(ghsm_vm_lease_status, owned_maps, 16);
ABI_OFFSET(ghsm_vm_lease_status, inflight_shares, 24);
ABI_OFFSET(ghsm_vm_lease_status, last_errno, 28);
_Static_assert(GHSM_SHARE_BLOB == 0xc0284714U, "legacy blob ioctl unchanged");
_Static_assert(GHSM_UNSHARE_BLOB == 0x40084715U, "legacy unshare ioctl unchanged");
_Static_assert(GHSM_SHARE_DMABUF == 0xc0304716U, "legacy dmabuf ioctl unchanged");
_Static_assert(GHSM_GET_LEASE_CAPS == 0x80104720U, "caps ioctl");
_Static_assert(GHSM_OPEN_VM_LEASE == 0x40084721U, "open ioctl returns fd separately");
_Static_assert(GHSM_SHARE_BLOB_LEASE == 0xc0384722U, "leased blob ioctl");
_Static_assert(GHSM_SHARE_DMABUF_LEASE == 0xc0404723U, "leased dmabuf ioctl");
_Static_assert(GHSM_SEAL_VM_LEASE == 0x00004724U, "seal has no payload or completion ack");
_Static_assert(GHSM_QUERY_VM_LEASE == 0x80204725U, "query ioctl");
_Static_assert(GHSM_UNSHARE_LEASE_PARCEL == 0x40084726U, "exact parcel unshare ioctl");
_Static_assert(GHSM_LEASE_ABI_VERSION == 1 && GHSM_LEASE_REQUIRED_FEATURES == 0xFULL,
               "version and required capability mask");
_Static_assert(GHSM_LEASE_OPEN == 1 && GHSM_LEASE_CLOSING == 2 &&
               GHSM_LEASE_COMPLETE == 3 && GHSM_LEASE_STALLED == 4, "wire state values");

static atomic_uint failures;
#define CHECK(condition, ...) do { \
    if (!(condition)) { \
        atomic_fetch_add_explicit(&failures, 1, memory_order_relaxed); \
        fprintf(stderr, "FAIL %s:%d (%s): ", __FILE__, __LINE__, #condition); \
        fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); \
    } \
} while (0)

static void require(bool condition)
{
    if (!condition) {
        fputs("test fixture allocation or pthread operation failed\n", stderr);
        abort();
    }
}

struct fake_map;
struct session {
    pthread_mutex_t lock;
    struct ghsm_lease_core core;
    struct fake_map *listed;
    void *vm_reference;
};

struct admitted_share {
    struct session *session;
    bool active;
};

struct fake_map {
    struct session *session;
    struct fake_map *next;
    bool linked;
    bool stalled;
    void *rm_parcel;
    void *gup_pages;
    void *dma_attachment;
};

static void lock(struct session *s) { require(pthread_mutex_lock(&s->lock) == 0); }
static void unlock(struct session *s) { require(pthread_mutex_unlock(&s->lock) == 0); }

static void session_init(struct session *s)
{
    memset(s, 0, sizeof(*s));
    require(pthread_mutex_init(&s->lock, NULL) == 0);
    s->vm_reference = malloc(1);
    require(s->vm_reference != NULL);
}

static struct admitted_share begin_share(struct session *s)
{
    struct admitted_share share = { .session = s };
    lock(s);
    share.active = ghsm_lease_core_begin_share(&s->core);
    unlock(s);
    return share;
}

static bool end_share(struct admitted_share *share)
{
    bool ended;
    if (!share->active)
        return false;
    lock(share->session);
    ended = ghsm_lease_core_end_share(&share->session->core);
    unlock(share->session);
    if (ended)
        share->active = false;
    return ended;
}

static struct fake_map *allocate_pinned_map(struct admitted_share *share, bool dma)
{
    struct fake_map *m;
    require(share->active);
    m = calloc(1, sizeof(*m));
    require(m != NULL);
    m->session = share->session;
    m->gup_pages = malloc(128);
    require(m->gup_pages != NULL);
    if (dma) {
        m->dma_attachment = malloc(1);
        require(m->dma_attachment != NULL);
    }
    lock(m->session);
    ghsm_lease_core_map_add(&m->session->core);
    unlock(m->session);
    return m;
}

static void rm_share_and_link(struct fake_map *m)
{
    require(m->rm_parcel == NULL && !m->linked);
    m->rm_parcel = malloc(1);
    require(m->rm_parcel != NULL);
    lock(m->session);
    m->next = m->session->listed;
    m->session->listed = m;
    m->linked = true;
    unlock(m->session);
}

/* List removal changes discovery only, never the production ownership charge. */
static void unlink_for_reaper(struct fake_map *m)
{
    struct fake_map **cursor;
    lock(m->session);
    cursor = &m->session->listed;
    while (*cursor && *cursor != m)
        cursor = &(*cursor)->next;
    require(*cursor == m);
    *cursor = m->next;
    m->next = NULL;
    m->linked = false;
    unlock(m->session);
}

static bool reclaim_rm(struct fake_map *m, int result)
{
    require(!m->linked && m->rm_parcel != NULL);
    if (result) {
        lock(m->session);
        if (!m->stalled) {
            ghsm_lease_core_stall(&m->session->core, result);
            m->stalled = true;
        }
        unlock(m->session);
        return false;
    }
    free(m->rm_parcel);
    m->rm_parcel = NULL;
    return true;
}

static bool explicitly_retry(struct fake_map *m)
{
    bool retry = false;
    lock(m->session);
    if (m->stalled) {
        retry = ghsm_lease_core_retry(&m->session->core);
        if (retry)
            m->stalled = false;
    }
    unlock(m->session);
    return retry;
}

static void unpin_and_detach(struct fake_map *m)
{
    require(!m->linked && m->rm_parcel == NULL);
    free(m->gup_pages);
    m->gup_pages = NULL;
    free(m->dma_attachment);
    m->dma_attachment = NULL;
}

static bool resource_free(struct fake_map *m)
{
    struct session *s = m->session;
    bool stalled = m->stalled;
    bool freed;
    if (m->linked || m->rm_parcel || m->gup_pages || m->dma_attachment)
        return false;
    free(m);  /* The concrete map and all its resource objects are gone first. */
    lock(s);
    freed = ghsm_lease_core_map_free(&s->core, stalled);
    unlock(s);
    return freed;
}

static bool begin_seal(struct session *s)
{
    bool begun;
    lock(s);
    begun = ghsm_lease_core_seal(&s->core);
    unlock(s);
    return begun;
}

static void drop_vm_reference_and_finish_seal(struct session *s)
{
    void *reference;
    lock(s);
    reference = s->vm_reference;
    s->vm_reference = NULL;
    unlock(s);
    free(reference);  /* Model the actual reference drop before seal_done. */
    lock(s);
    ghsm_lease_core_seal_done(&s->core);
    unlock(s);
}

/* Cancellation has no separate completion operation: it is the same seal
 * admission fence used when the caller closes an observer. It frees no map. */
static void cancel_admission(struct session *s)
{
    if (begin_seal(s))
        drop_vm_reference_and_finish_seal(s);
}

static void expect(struct session *s, __u32 state, __u64 owned, __u32 inflight, __u64 stalled)
{
    struct ghsm_lease_core snapshot;
    lock(s);
    snapshot = s->core;
    unlock(s);
    CHECK(ghsm_lease_core_state(&snapshot) == state && snapshot.owned_maps == owned &&
          snapshot.inflight_shares == inflight && snapshot.stalled_maps == stalled,
          "state=%u owned=%llu inflight=%u stalled=%llu; expected %u/%llu/%u/%llu",
          ghsm_lease_core_state(&snapshot), (unsigned long long)snapshot.owned_maps,
          snapshot.inflight_shares, (unsigned long long)snapshot.stalled_maps,
          state, (unsigned long long)owned, inflight, (unsigned long long)stalled);
}

static void session_destroy(struct session *s)
{
    expect(s, GHSM_LEASE_COMPLETE, 0, 0, 0);
    require(s->listed == NULL && s->vm_reference == NULL);
    require(pthread_mutex_destroy(&s->lock) == 0);
}

static void test_normal_completion(void)
{
    struct session s;
    struct admitted_share share;
    struct fake_map *m;
    session_init(&s);
    share = begin_share(&s);
    CHECK(share.active, "open session admits share");
    m = allocate_pinned_map(&share, true);
    rm_share_and_link(m);
    CHECK(end_share(&share), "accepted share leaves admission");
    CHECK(begin_seal(&s), "first seal starts");
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    drop_vm_reference_and_finish_seal(&s);
    unlink_for_reaper(m);
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    CHECK(!resource_free(m), "list_del cannot complete an RM parcel with pins");
    CHECK(reclaim_rm(m, 0), "RM accepted reclaim");
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    CHECK(!resource_free(m), "RM success alone cannot acknowledge unpin");
    unpin_and_detach(m);
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    CHECK(resource_free(m), "resource-free map discharges actual ownership");
    session_destroy(&s);
}

static void test_sealing_and_partial_failed_share(void)
{
    struct session s;
    struct admitted_share share;
    struct fake_map *m;
    session_init(&s);
    share = begin_share(&s);
    CHECK(share.active, "share admission precedes a seal");
    CHECK(begin_seal(&s), "seal starts while admitted share is in progress");
    CHECK(!begin_share(&s).active, "sealed session rejects subsequent admission");
    expect(&s, GHSM_LEASE_CLOSING, 0, 1, 0);
    m = allocate_pinned_map(&share, false); /* GUP succeeded, RM share then failed. */
    drop_vm_reference_and_finish_seal(&s);
    expect(&s, GHSM_LEASE_CLOSING, 1, 1, 0);
    CHECK(!resource_free(m), "partial share failure still owns its GUP resources");
    unpin_and_detach(m);
    CHECK(resource_free(m), "failed share cleanup frees its concrete resources");
    expect(&s, GHSM_LEASE_CLOSING, 0, 1, 0);
    CHECK(end_share(&share), "completion must also wait for the admitted call");
    CHECK(!end_share(&share), "duplicate end cannot underflow admission");
    session_destroy(&s);

    session_init(&s);
    CHECK(begin_seal(&s), "empty session starts sealing");
    expect(&s, GHSM_LEASE_CLOSING, 0, 0, 0);
    CHECK(!begin_seal(&s), "duplicate seal does not clear the sealing phase");
    expect(&s, GHSM_LEASE_CLOSING, 0, 0, 0);
    drop_vm_reference_and_finish_seal(&s);
    session_destroy(&s);
}

static void test_stalled_retry_and_cancel(void)
{
    struct session s;
    struct admitted_share share;
    struct fake_map *m;
    unsigned int i;
    session_init(&s);
    share = begin_share(&s);
    m = allocate_pinned_map(&share, false);
    rm_share_and_link(m);
    CHECK(end_share(&share), "share ended");
    cancel_admission(&s);
    unlink_for_reaper(m);
    CHECK(!reclaim_rm(m, -EAGAIN), "failed RM reclaim remains owned");
    expect(&s, GHSM_LEASE_STALLED, 1, 0, 1);
    CHECK(!resource_free(m) && m->rm_parcel && m->gup_pages,
          "reaper list removal and failure leave concrete resources intact");
    for (i = 0; i < 32; i++) {
        cancel_admission(&s);
        CHECK(!begin_seal(&s), "duplicate seal is idempotent");
        expect(&s, GHSM_LEASE_STALLED, 1, 0, 1);
    }
    lock(&s);
    CHECK(s.core.last_errno == -EAGAIN, "query retains the real stalled reason");
    unlock(&s);
    CHECK(explicitly_retry(m), "explicit retry removes only the stalled tag");
    CHECK(!explicitly_retry(m), "retry cannot consume another map's tag");
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    CHECK(!reclaim_rm(m, -EIO), "another real RM failure stalls it again");
    expect(&s, GHSM_LEASE_STALLED, 1, 0, 1);
    CHECK(explicitly_retry(m) && reclaim_rm(m, 0), "explicit retry can eventually reclaim");
    expect(&s, GHSM_LEASE_CLOSING, 1, 0, 0);
    unpin_and_detach(m);
    CHECK(resource_free(m), "retry acknowledges only after actual resource free");
    lock(&s);
    CHECK(s.core.last_errno == 0, "final resource free clears the last failure");
    unlock(&s);
    session_destroy(&s);
}

static void test_two_sessions(void)
{
    struct session a, b;
    struct admitted_share sa, sb;
    struct fake_map *ma, *mb;
    session_init(&a);
    session_init(&b);
    sa = begin_share(&a);
    sb = begin_share(&b);
    ma = allocate_pinned_map(&sa, false);
    mb = allocate_pinned_map(&sb, true);
    rm_share_and_link(ma);
    rm_share_and_link(mb);
    CHECK(end_share(&sa) && end_share(&sb), "both independent admissions finish");
    cancel_admission(&a);
    unlink_for_reaper(ma);
    CHECK(!reclaim_rm(ma, -EPERM), "only A stalls");
    expect(&a, GHSM_LEASE_STALLED, 1, 0, 1);
    expect(&b, GHSM_LEASE_OPEN, 1, 0, 0);
    cancel_admission(&b);
    unlink_for_reaper(mb);
    CHECK(reclaim_rm(mb, 0), "B reclaims normally");
    unpin_and_detach(mb);
    CHECK(resource_free(mb), "B completes independently");
    expect(&a, GHSM_LEASE_STALLED, 1, 0, 1);
    session_destroy(&b);
    CHECK(explicitly_retry(ma) && reclaim_rm(ma, 0), "A needs its own retry");
    unpin_and_detach(ma);
    CHECK(resource_free(ma), "A finally completes");
    session_destroy(&a);
}

struct admitted_race {
    struct session session;
    struct fake_map *map;
    pthread_barrier_t admitted, staged, finish;
};

static void barrier(pthread_barrier_t *b)
{
    int ret = pthread_barrier_wait(b);
    require(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *admitted_worker(void *arg)
{
    struct admitted_race *r = arg;
    struct admitted_share share = begin_share(&r->session);
    CHECK(share.active, "race: admitted call owns its inflight charge");
    barrier(&r->admitted);
    /* This allocation races the seal thread's admission fence and ref drop. */
    r->map = allocate_pinned_map(&share, true);
    rm_share_and_link(r->map);
    barrier(&r->staged);
    barrier(&r->finish);
    CHECK(end_share(&share), "race: admitted call finishes after seal");
    return NULL;
}

static void *seal_worker(void *arg)
{
    struct admitted_race *r = arg;
    barrier(&r->admitted);
    CHECK(begin_seal(&r->session), "race: seal wins the admission fence");
    drop_vm_reference_and_finish_seal(&r->session);
    barrier(&r->staged);
    return NULL;
}

static void test_seal_with_admitted_share(void)
{
    struct admitted_race r;
    pthread_t share_thread, seal_thread;
    session_init(&r.session);
    r.map = NULL;
    require(pthread_barrier_init(&r.admitted, NULL, 2) == 0);
    require(pthread_barrier_init(&r.staged, NULL, 3) == 0);
    require(pthread_barrier_init(&r.finish, NULL, 2) == 0);
    require(pthread_create(&share_thread, NULL, admitted_worker, &r) == 0);
    require(pthread_create(&seal_thread, NULL, seal_worker, &r) == 0);
    barrier(&r.staged);
    expect(&r.session, GHSM_LEASE_CLOSING, 1, 1, 0);
    CHECK(r.map && r.map->rm_parcel && r.map->gup_pages && r.map->dma_attachment,
          "race: resources remain real while admission has not returned");
    CHECK(!begin_share(&r.session).active, "race: later admission is rejected");
    barrier(&r.finish);
    require(pthread_join(share_thread, NULL) == 0);
    require(pthread_join(seal_thread, NULL) == 0);
    expect(&r.session, GHSM_LEASE_CLOSING, 1, 0, 0);
    unlink_for_reaper(r.map);
    CHECK(reclaim_rm(r.map, 0), "race: final RM reclaim succeeds");
    unpin_and_detach(r.map);
    CHECK(resource_free(r.map), "race: resource free, not sealing, completes it");
    session_destroy(&r.session);
    require(pthread_barrier_destroy(&r.finish) == 0);
    require(pthread_barrier_destroy(&r.staged) == 0);
    require(pthread_barrier_destroy(&r.admitted) == 0);
}

int main(void)
{
    unsigned int count;
    test_normal_completion();
    test_sealing_and_partial_failed_share();
    test_stalled_retry_and_cancel();
    test_two_sessions();
    test_seal_with_admitted_share();
    count = atomic_load_explicit(&failures, memory_order_relaxed);
    if (count) {
        fprintf(stderr, "%u FAILURE(S)\n", count);
        return 1;
    }
    puts("lease production-helper/UAPI harness passed; kernel VM/GUP not tested");
    return 0;
}

/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Production lease implementation over deterministic files/RM resources.
 * This validates ownership/cancellation concurrency, not real Gunyah/GUP. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "../ghsm_lease_state.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned int __poll_t;
typedef void poll_table;
#define __user
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define GFP_KERNEL 0
#define THIS_MODULE ((void *)1)
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define WARN_ON(c) ((c) ? (abort(), 1) : 0)

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h) ((h)->next = (h)->prev = (h))
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; }
static void list_del_init(struct list_head *n) { list_del(n); INIT_LIST_HEAD(n); }
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for (p = list_entry((h)->next, __typeof__(*p), m); &p->m != (h); \
      p = list_entry(p->m.next, __typeof__(*p), m))
#define list_for_each_entry_safe(p,n,h,m) \
 for (p = list_entry((h)->next, __typeof__(*p), m), n = list_entry(p->m.next, __typeof__(*p), m); \
      &p->m != (h); p = n, n = list_entry(n->m.next, __typeof__(*n), m))

typedef struct { atomic_flag held; } spinlock_t;
static _Thread_local spinlock_t *current_spin;
static void spin_lock_init(spinlock_t *l) { atomic_flag_clear(&l->held); }
static void spin_lock(spinlock_t *l)
{
 assert(!current_spin);
 while (atomic_flag_test_and_set_explicit(&l->held, memory_order_acquire)) sched_yield();
 current_spin = l;
}
static void spin_unlock(spinlock_t *l)
{ assert(current_spin == l); current_spin = NULL; atomic_flag_clear_explicit(&l->held, memory_order_release); }
#define spin_lock_irqsave(l,f) do { (f) = 0; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); spin_unlock(l); } while (0)
static pthread_mutex_t ghsm_lock = PTHREAD_MUTEX_INITIALIZER;
static void mutex_lock(pthread_mutex_t *m) { assert(!current_spin); assert(!pthread_mutex_lock(m)); }
static void mutex_unlock(pthread_mutex_t *m) { assert(!pthread_mutex_unlock(m)); }

struct kref { atomic_uint count; };
static void kref_init(struct kref *r) { atomic_init(&r->count, 1); }
static void kref_get(struct kref *r) { assert(atomic_fetch_add(&r->count, 1)); }
static void kref_put(struct kref *r, void (*done)(struct kref *))
{ unsigned int old = atomic_fetch_sub(&r->count, 1); assert(old); if (old == 1) done(r); }
typedef struct { atomic_uint wakes; } wait_queue_head_t;
static void init_waitqueue_head(wait_queue_head_t *w) { atomic_init(&w->wakes, 0); }
static void wake_up_interruptible(wait_queue_head_t *w) { atomic_fetch_add(&w->wakes, 1); }

struct inode { int unused; };
struct file;
struct file_operations {
 void *owner;
 long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
 long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
 __poll_t (*poll)(struct file *, poll_table *);
 int (*release)(struct inode *, struct file *);
};
struct file { atomic_uint refs; const struct file_operations *f_op; void *private_data; };
static struct file *fds[128];
static pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint module_refs, vm_releases, resource_releases, scheduled;
static void *kzalloc(size_t n, int flags) { (void)flags; return calloc(1,n); }
static void kfree(void *p) { free(p); }
static void __module_get(void *m) { (void)m; atomic_fetch_add(&module_refs,1); }
static void module_put(void *m) { (void)m; assert(atomic_fetch_sub(&module_refs,1)); }
static struct file *get_file(struct file *f) { assert(atomic_fetch_add(&f->refs,1)); return f; }
static void fput(struct file *f)
{
 unsigned int old;
 assert(!current_spin && f);
 old = atomic_fetch_sub(&f->refs,1); assert(old);
 if (old != 1) return;
 if (f->f_op && f->f_op->release) f->f_op->release(NULL,f);
 else atomic_fetch_add(&vm_releases,1);
 free(f);
}
static struct file *fget(int fd)
{
 struct file *f = NULL;
 mutex_lock(&fd_lock);
 if (fd >= 0 && fd < 128 && fds[fd]) f = get_file(fds[fd]);
 mutex_unlock(&fd_lock);
 return f;
}
static int install_file(struct file *f)
{
 int i;
 mutex_lock(&fd_lock);
 for (i=0;i<128;i++) if (!fds[i]) { fds[i]=f; break; }
 mutex_unlock(&fd_lock);
 assert(i<128); return i;
}
static void close_fd(int fd)
{
 struct file *f;
 mutex_lock(&fd_lock); f=fds[fd]; assert(f); fds[fd]=NULL; mutex_unlock(&fd_lock); fput(f);
}
static int anon_inode_getfd(const char *name, const struct file_operations *ops, void *data, int flags)
{
 struct file *f=calloc(1,sizeof(*f));
 assert(f && (flags & O_CLOEXEC)); (void)name;
 atomic_init(&f->refs,1); f->f_op=ops; f->private_data=data; return install_file(f);
}
static void poll_wait(struct file *f, wait_queue_head_t *w, poll_table *p) { (void)f;(void)w;(void)p; }
static int copy_from_user(void *to,const void *from,size_t n) { memcpy(to,from,n);return 0; }
static int copy_to_user(void *to,const void *from,size_t n) { memcpy(to,from,n);return 0; }

struct ghsm_lease;
struct ghsm_receipt;
struct ghsm_map {
 struct list_head node;
 struct file *vm_file;
 struct ghsm_lease *lease;
 struct ghsm_receipt *receipt;
 u32 label;
 bool creating, dying, reset_failed;
 int retries;
 void *pins;
};
static LIST_HEAD(ghsm_maps);
static void *ghsm_get_ghvm(int fd,struct file **out)
{
 struct file *f=fget(fd);
 if (!f) return NULL;
 if (f->f_op) { fput(f);return NULL; }
 *out=f;return f->private_data;
}
static int ghsm_try_destroy(struct ghsm_map *m);
#include "../ghsm_lease_impl.c.inc"

static void ghsm_lease_schedule_reaper(void) { atomic_fetch_add(&scheduled,1); }
static atomic_int rm_result;
static atomic_int gate_stage;
static pthread_barrier_t entered, resume_work;
static int ghsm_try_destroy(struct ghsm_map *m)
{
 int result;
 struct file *vm_file;
 struct ghsm_lease *lease=m->lease;
 struct ghsm_receipt *receipt=m->receipt;
 ghsm_lease_reclaim_started(m);
 if (atomic_load(&gate_stage)==1) { pthread_barrier_wait(&entered);pthread_barrier_wait(&resume_work); }
 result=atomic_load(&rm_result);
 if (result) {
  vm_file=ghsm_map_take_vm_file(m);if(vm_file)fput(vm_file);
  ghsm_lease_reclaim_failed(m,result,false);return result;
 }
 vm_file=ghsm_map_take_vm_file(m);
 ghsm_lease_forget_map_pointer(m);
 if (atomic_load(&gate_stage)==2) { pthread_barrier_wait(&entered);pthread_barrier_wait(&resume_work); }
 assert(m->pins);free(m->pins);m->pins=NULL;atomic_fetch_add(&resource_releases,1);
 if(vm_file)fput(vm_file);
 free(m);
 ghsm_lease_map_freed(lease,receipt);
 return 0;
}

static int new_vm(void)
{
 struct file *f=calloc(1,sizeof(*f));assert(f);
 atomic_init(&f->refs,1);f->private_data=f;return install_file(f);
}
static struct ghsm_lease *lease_of(int fd) { return fds[fd]->private_data; }
static struct ghsm_map *publish_map(struct ghsm_lease *lease,struct file *vm_file,
                                   struct ghsm_receipt *r)
{
 struct ghsm_map *m=calloc(1,sizeof(*m));assert(m);
 INIT_LIST_HEAD(&m->node);m->vm_file=get_file(vm_file);m->label=r->label;
 m->pins=malloc(128);assert(m->pins);
 ghsm_lease_map_attached(m,r);
 mutex_lock(&ghsm_lock);list_add_tail(&m->node,&ghsm_maps);mutex_unlock(&ghsm_lock);
 ghsm_lease_share_finish(lease,r,true);
 return m;
}
static u64 share_one(int leasefd,int vmfd,u32 label,struct ghsm_map **out)
{
 struct ghsm_lease *lease=lease_of(leasefd);
 struct file *vm=fget(vmfd);struct ghsm_receipt *r;u64 id;
 r=ghsm_lease_share_begin(lease,vm,label);assert(!IS_ERR(r));id=r->id;
 *out=publish_map(lease,vm,r);fput(vm);return id;
}
static struct ghsm_vm_lease_status status_of(int fd)
{
 struct ghsm_vm_lease_status s;
 assert(!ghsm_lease_ioctl(fds[fd],GHSM_QUERY_VM_LEASE,(unsigned long)&s));return s;
}
static void clean_session(int leasefd,int vmfd)
{ close_fd(leasefd);close_fd(vmfd);assert(!atomic_load(&module_refs)); }

static void test_exact_receipt(void)
{
 int vmfd=new_vm(),leasefd=ghsm_open_vm_lease(vmfd);
 struct ghsm_map *m;struct ghsm_receipt *r;u64 id;
 struct ghsm_lease *lease=lease_of(leasefd);
 unsigned int before=atomic_load(&resource_releases);
 assert(leasefd>=0);
 id=share_one(leasefd,vmfd,17,&m);
 atomic_store(&rm_result,-EBUSY);
 assert(ghsm_lease_unshare(lease,id)==-EBUSY);
 assert(status_of(leasefd).owned_maps==1);
 r=ghsm_lease_share_begin(lease,fds[vmfd],17);
 assert(IS_ERR(r)&&PTR_ERR(r)==-EBUSY); /* dying remains an owner */
 assert(ghsm_lease_unshare(lease,id+1)==-ENOENT);
 atomic_store(&rm_result,0);
 assert(!ghsm_lease_unshare(lease,id));
 assert(atomic_load(&resource_releases)==before+1);
 assert(ghsm_lease_unshare(lease,id)==-ENOENT); /* consumed receipt, not false success */
 assert(status_of(leasefd).state==GHSM_LEASE_OPEN);
 assert(!ghsm_lease_seal(lease));
 assert(status_of(leasefd).state==GHSM_LEASE_COMPLETE);
 assert(ghsm_lease_poll(fds[leasefd],NULL)&EPOLLIN);
 clean_session(leasefd,vmfd);
}

struct worker { struct ghsm_lease *lease;u64 id;int result; };
static void *unshare_worker(void *arg)
{ struct worker *w=arg;w->result=ghsm_lease_unshare(w->lease,w->id);return NULL; }
static void test_seal_reclaim_race(int stage,int rm_error)
{
 int vmfd=new_vm(),leasefd=ghsm_open_vm_lease(vmfd);
 struct ghsm_map *m;pthread_t thread;
 struct worker w={.lease=lease_of(leasefd)};
 unsigned int released=atomic_load(&resource_releases);
 w.id=share_one(leasefd,vmfd,91,&m);
 assert(!pthread_barrier_init(&entered,NULL,2));assert(!pthread_barrier_init(&resume_work,NULL,2));
 atomic_store(&gate_stage,stage);atomic_store(&rm_result,rm_error);
 assert(!pthread_create(&thread,NULL,unshare_worker,&w));
 pthread_barrier_wait(&entered);
 assert(!ghsm_lease_seal(w.lease));
 assert(!ghsm_lease_seal(w.lease));
 assert(status_of(leasefd).state==GHSM_LEASE_CLOSING);
 assert(atomic_load(&resource_releases)==released);
 assert(ghsm_lease_unshare(w.lease,w.id)==-EAGAIN);
 close_fd(vmfd); /* query/reclaim no longer has any VM fd */
 pthread_barrier_wait(&resume_work);assert(!pthread_join(thread,NULL));
 atomic_store(&gate_stage,0);
 if(rm_error) {
  assert(w.result==rm_error && status_of(leasefd).owned_maps==1);
  ghsm_lease_reclaim_failed(m,rm_error,true);
  assert(status_of(leasefd).state==GHSM_LEASE_STALLED);
  assert(ghsm_lease_poll(fds[leasefd],NULL)==EPOLLERR);
  atomic_store(&rm_result,0);assert(!ghsm_lease_unshare(w.lease,w.id));
 } else assert(!w.result);
 assert(status_of(leasefd).state==GHSM_LEASE_COMPLETE);
 assert(atomic_load(&resource_releases)==released+1);
 close_fd(leasefd);assert(!atomic_load(&module_refs));
 pthread_barrier_destroy(&entered);pthread_barrier_destroy(&resume_work);
}

static void test_late_creation_and_error(void)
{
 int vmfd=new_vm(),leasefd=ghsm_open_vm_lease(vmfd);
 struct ghsm_lease *lease=lease_of(leasefd);
 struct file *vm=fget(vmfd);
 struct ghsm_receipt *r=ghsm_lease_share_begin(lease,vm,100);
 struct ghsm_map *m;u64 id=r->id;
 assert(!IS_ERR(r));assert(!ghsm_lease_seal(lease));
 assert(status_of(leasefd).state==GHSM_LEASE_CLOSING);
 m=publish_map(lease,vm,r);
 assert(m->dying&&!m->vm_file);fput(vm);close_fd(vmfd);
 atomic_store(&rm_result,0);assert(!ghsm_lease_unshare(lease,id));
 assert(status_of(leasefd).state==GHSM_LEASE_COMPLETE);
 close_fd(leasefd);assert(!atomic_load(&module_refs));

 vmfd=new_vm();leasefd=ghsm_open_vm_lease(vmfd);lease=lease_of(leasefd);
 r=ghsm_lease_share_begin(lease,fds[vmfd],101);assert(!IS_ERR(r));
 m=calloc(1,sizeof(*m));assert(m);m->vm_file=get_file(fds[vmfd]);m->pins=malloc(64);assert(m->pins);
 ghsm_lease_map_attached(m,r);assert(!ghsm_lease_seal(lease));
 assert(status_of(leasefd).owned_maps==1&&status_of(leasefd).inflight_shares==1);
 vm=ghsm_map_take_vm_file(m);ghsm_lease_forget_map_pointer(m);if(vm)fput(vm);
 free(m->pins);free(m); /* backend partial failure really finishes first */
 ghsm_lease_share_finish(lease,r,false);
 assert(status_of(leasefd).state==GHSM_LEASE_COMPLETE);
 clean_session(leasefd,vmfd);
}

static void test_fd_release_keeps_resources(void)
{
 int vmfd=new_vm(),leasefd=ghsm_open_vm_lease(vmfd);
 struct ghsm_map *m;struct ghsm_lease *lease=lease_of(leasefd);
 share_one(leasefd,vmfd,200,&m);
 close_fd(leasefd);
 assert(atomic_load(&module_refs)==1&&m->dying&&!m->vm_file);
 assert(lease->core.owned_maps==1); /* map, not closed fd, owns this reference */
 close_fd(vmfd);
 mutex_lock(&ghsm_lock);list_del_init(&m->node);mutex_unlock(&ghsm_lock);
 atomic_store(&rm_result,0);assert(!ghsm_try_destroy(m));
 assert(!atomic_load(&module_refs));
}

static void test_other_vm_isolation(void)
{
 int a=new_vm(),b=new_vm(),la=ghsm_open_vm_lease(a),lb=ghsm_open_vm_lease(b);
 struct ghsm_map *ma,*mb;u64 ia,ib;struct ghsm_receipt *r;
 ia=share_one(la,a,1,&ma);ib=share_one(lb,b,1,&mb);
 r=ghsm_lease_share_begin(lease_of(la),fds[b],3);
 assert(IS_ERR(r)&&PTR_ERR(r)==-EXDEV);
 assert(!ghsm_lease_seal(lease_of(la)));
 assert(ma->dying&&!ma->vm_file&&!mb->dying&&mb->vm_file);
 atomic_store(&rm_result,0);assert(!ghsm_lease_unshare(lease_of(la),ia));
 assert(status_of(la).state==GHSM_LEASE_COMPLETE&&status_of(lb).state==GHSM_LEASE_OPEN);
 close_fd(la);close_fd(a);
 assert(!ghsm_lease_unshare(lease_of(lb),ib));
 close_fd(lb);close_fd(b);assert(!atomic_load(&module_refs));
}

int main(void)
{
 test_exact_receipt();
 test_seal_reclaim_race(1,-EBUSY);
 test_seal_reclaim_race(2,0);
 test_late_creation_and_error();
 test_fd_release_keeps_resources();
 test_other_vm_isolation();
 assert(ghsm_maps.next==&ghsm_maps);
 puts("production lease implementation harness: all cases passed (mock files/RM only)");
 return 0;
}

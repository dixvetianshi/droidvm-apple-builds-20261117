/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Session lock owns admission, receipts, counters and leased map VM refs.
 * ghsm_lock owns map list membership. If nested: ghsm_lock -> session lock.
 * No RM RPC, resource release, fput or wait runs under the session lock. */

struct ghsm_lease {
	struct kref refs;
	spinlock_t lock;
	struct ghsm_lease_core core;
	struct list_head receipts;
	wait_queue_head_t wait;
	struct file *vm_file; /* OPEN identity ref; transferred by SEAL */
	u64 generation;
	u64 next_parcel_id;
};

struct ghsm_receipt {
	struct list_head node;
	struct ghsm_lease *lease;
	struct ghsm_map *map; /* cleared before map metadata is freed */
	u64 id;
	u32 label;
	bool attached;
	bool reclaiming;
	bool completed;
	bool stalled;
	int last_errno;
};

static u64 ghsm_lease_generation; /* ghsm_lock */
static const struct file_operations ghsm_lease_fops;
static void ghsm_lease_schedule_reaper(void);

static void ghsm_lease_release_ref(struct kref *refs)
{
	struct ghsm_lease *lease = container_of(refs, struct ghsm_lease, refs);
	struct ghsm_receipt *r, *tmp;

	/* No fd, map or in-flight owner remains at the last reference. */
	list_for_each_entry_safe(r, tmp, &lease->receipts, node) {
		list_del(&r->node);
		kfree(r);
	}
	if (lease->vm_file)
		fput(lease->vm_file);
	kfree(lease);
	module_put(THIS_MODULE);
}

static struct ghsm_receipt *ghsm_lease_find_locked(struct ghsm_lease *lease, u64 id)
{
	struct ghsm_receipt *r;

	list_for_each_entry(r, &lease->receipts, node)
		if (r->id == id)
			return r;
	return NULL;
}

static struct file *ghsm_map_take_vm_file(struct ghsm_map *m)
{
	struct file *file;
	unsigned long flags;

	if (!m->lease) {
		file = m->vm_file;
		m->vm_file = NULL;
		return file;
	}
	spin_lock_irqsave(&m->lease->lock, flags);
	file = m->vm_file;
	m->vm_file = NULL;
	spin_unlock_irqrestore(&m->lease->lock, flags);
	return file;
}

static struct file *ghsm_map_get_vm_file(struct ghsm_map *m)
{
	struct file *file;
	unsigned long flags;

	if (!m->lease)
		return m->vm_file ? get_file(m->vm_file) : NULL;
	spin_lock_irqsave(&m->lease->lock, flags);
	file = m->vm_file ? get_file(m->vm_file) : NULL;
	spin_unlock_irqrestore(&m->lease->lock, flags);
	return file;
}

static bool ghsm_map_has_vm_file(struct ghsm_map *m)
{
	unsigned long flags;
	bool has_file;

	if (!m->lease)
		return !!m->vm_file;
	spin_lock_irqsave(&m->lease->lock, flags);
	has_file = !!m->vm_file;
	spin_unlock_irqrestore(&m->lease->lock, flags);
	return has_file;
}

static bool ghsm_map_vm_file_equals(struct ghsm_map *m, struct file *file)
{
	unsigned long flags;
	bool same;

	if (!m->lease)
		return m->vm_file == file;
	spin_lock_irqsave(&m->lease->lock, flags);
	same = m->vm_file == file;
	spin_unlock_irqrestore(&m->lease->lock, flags);
	return same;
}

static void ghsm_lease_forget_map_pointer(struct ghsm_map *m)
{
	unsigned long flags;

	if (!m->lease)
		return;
	spin_lock_irqsave(&m->lease->lock, flags);
	m->receipt->map = NULL;
	/* It remains charged/reclaiming until actual resource release finishes. */
	spin_unlock_irqrestore(&m->lease->lock, flags);
}

static void ghsm_lease_map_attached(struct ghsm_map *m, struct ghsm_receipt *r)
{
	unsigned long flags;

	if (!r)
		return;
	m->lease = r->lease;
	m->receipt = r;
	m->creating = true;
	kref_get(&r->lease->refs); /* map resource ownership, not list membership */
	spin_lock_irqsave(&r->lease->lock, flags);
	r->map = m;
	r->attached = true;
	ghsm_lease_core_map_add(&r->lease->core);
	spin_unlock_irqrestore(&r->lease->lock, flags);
}

static void ghsm_lease_map_freed(struct ghsm_lease *lease, struct ghsm_receipt *r)
{
	unsigned long flags;

	/* Called after RM success AND the entire map resource/free routine. */
	spin_lock_irqsave(&lease->lock, flags);
	r->map = NULL;
	r->completed = true;
	r->reclaiming = false;
	r->last_errno = 0;
	WARN_ON(!ghsm_lease_core_map_free(&lease->core, r->stalled));
	r->attached = false;
	r->stalled = false;
	spin_unlock_irqrestore(&lease->lock, flags);
	wake_up_interruptible(&lease->wait);
	kref_put(&lease->refs, ghsm_lease_release_ref);
}

static void ghsm_lease_reclaim_started(struct ghsm_map *m)
{
	unsigned long flags;

	if (!m->lease)
		return;
	spin_lock_irqsave(&m->lease->lock, flags);
	m->receipt->reclaiming = true;
	spin_unlock_irqrestore(&m->lease->lock, flags);
}

static void ghsm_lease_reclaim_failed(struct ghsm_map *m, int error, bool stalled)
{
	unsigned long flags;

	if (!m->lease)
		return;
	spin_lock_irqsave(&m->lease->lock, flags);
	m->receipt->last_errno = error;
	m->lease->core.last_errno = error;
	if (stalled && !m->receipt->stalled) {
		m->receipt->stalled = true;
		ghsm_lease_core_stall(&m->lease->core, error);
	}
	spin_unlock_irqrestore(&m->lease->lock, flags);
	wake_up_interruptible(&m->lease->wait);
}

static void ghsm_lease_requeued(struct ghsm_map *m)
{
	unsigned long flags;

	if (!m->lease)
		return;
	spin_lock_irqsave(&m->lease->lock, flags);
	m->receipt->reclaiming = false;
	spin_unlock_irqrestore(&m->lease->lock, flags);
}

static void ghsm_lease_parked(struct ghsm_map *m)
{
	unsigned long flags;

	if (!m->lease)
		return;
	spin_lock_irqsave(&m->lease->lock, flags);
	if (!m->receipt->stalled) {
		m->receipt->stalled = true;
		ghsm_lease_core_stall(&m->lease->core, m->receipt->last_errno);
	}
	spin_unlock_irqrestore(&m->lease->lock, flags);
	wake_up_interruptible(&m->lease->wait);
}

static struct ghsm_lease *ghsm_lease_get_fd(int fd, struct file **out_file)
{
	struct file *file = fget(fd);

	if (!file || file->f_op != &ghsm_lease_fops) {
		if (file)
			fput(file);
		return ERR_PTR(-EBADF);
	}
	*out_file = file;
	return file->private_data;
}

static struct ghsm_receipt *ghsm_lease_share_begin(struct ghsm_lease *lease,
					       struct file *vm_file, u32 label)
{
	struct ghsm_receipt *r, *other;
	unsigned long flags;
	int error = 0;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);
	spin_lock_irqsave(&lease->lock, flags);
	if (lease->core.sealed)
		error = -EPIPE;
	else if (lease->vm_file != vm_file)
		error = -EXDEV;
	else if (lease->next_parcel_id == U64_MAX ||
		 lease->core.inflight_shares == U32_MAX)
		error = -EOVERFLOW;
	if (!error)
		list_for_each_entry(other, &lease->receipts, node)
			if (other->label == label && !other->completed) {
				error = -EBUSY; /* includes dying/reclaiming, unlike find_map */
				break;
			}
	if (!error) {
		r->lease = lease;
		r->id = ++lease->next_parcel_id;
		r->label = label;
		r->reclaiming = true; /* producer owns it until ioctl completion */
		WARN_ON(!ghsm_lease_core_begin_share(&lease->core));
		list_add_tail(&r->node, &lease->receipts);
	}
	spin_unlock_irqrestore(&lease->lock, flags);
	if (error) {
		kfree(r);
		return ERR_PTR(error);
	}
	return r;
}

static void ghsm_lease_share_finish(struct ghsm_lease *lease,
				  struct ghsm_receipt *r, bool shared)
{
	unsigned long flags;
	struct file *vm_file = NULL;
	bool map_ref = false;

	if (!shared) {
		/* Backend error cleanup has already unpinned/freed partial resources. */
		spin_lock_irqsave(&lease->lock, flags);
		if (r->attached) {
			WARN_ON(!ghsm_lease_core_map_free(&lease->core, r->stalled));
			map_ref = true;
		}
		list_del(&r->node);
		WARN_ON(!ghsm_lease_core_end_share(&lease->core));
		spin_unlock_irqrestore(&lease->lock, flags);
		kfree(r);
		wake_up_interruptible(&lease->wait);
		if (map_ref)
			kref_put(&lease->refs, ghsm_lease_release_ref);
		return;
	}
	mutex_lock(&ghsm_lock);
	spin_lock_irqsave(&lease->lock, flags);
	/* Reaper cannot reclaim a creating map before producer access ends. */
	if (WARN_ON(!r->map)) {
		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		return;
	}
	r->map->creating = false;
	if (lease->core.sealed) {
		r->map->dying = true;
		r->map->retries = 0;
		vm_file = r->map->vm_file;
		r->map->vm_file = NULL;
	}
	r->reclaiming = false;
	spin_unlock_irqrestore(&lease->lock, flags);
	mutex_unlock(&ghsm_lock);
	if (vm_file)
		fput(vm_file);
	/* r may now be reclaimed/acknowledged; do not dereference it again. */
	spin_lock_irqsave(&lease->lock, flags);
	WARN_ON(!ghsm_lease_core_end_share(&lease->core));
	spin_unlock_irqrestore(&lease->lock, flags);
	wake_up_interruptible(&lease->wait);
	ghsm_lease_schedule_reaper();
}

static int ghsm_lease_seal(struct ghsm_lease *lease)
{
	struct ghsm_receipt *r;
	struct ghsm_map *m;
	struct file *file;
	unsigned long flags;

	mutex_lock(&ghsm_lock);
	spin_lock_irqsave(&lease->lock, flags);
	if (!ghsm_lease_core_seal(&lease->core)) {
		int ret = lease->core.sealing ? -EAGAIN : 0;

		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		return ret;
	}
	file = lease->vm_file;
	lease->vm_file = NULL;
	spin_unlock_irqrestore(&lease->lock, flags);
	list_for_each_entry(m, &ghsm_maps, node)
		if (m->lease == lease) {
			m->dying = true;
			if (!m->reset_failed)
				m->retries = 0;
		}
	mutex_unlock(&ghsm_lock);
	if (file)
		fput(file);
	/* Receipts cover listed, creating and temporarily detached reclaimers.
	 * Transfer each VM ref under its owning lock, then fput outside it. */
	for (;;) {
		file = NULL;
		spin_lock_irqsave(&lease->lock, flags);
		list_for_each_entry(r, &lease->receipts, node)
			if (r->map && r->map->vm_file) {
				file = r->map->vm_file;
				r->map->vm_file = NULL;
				break;
			}
		spin_unlock_irqrestore(&lease->lock, flags);
		if (!file)
			break;
		fput(file);
	}
	spin_lock_irqsave(&lease->lock, flags);
	ghsm_lease_core_seal_done(&lease->core);
	spin_unlock_irqrestore(&lease->lock, flags);
	wake_up_interruptible(&lease->wait);
	ghsm_lease_schedule_reaper();
	return 0;
}

static int ghsm_lease_unshare(struct ghsm_lease *lease, u64 id)
{
	struct ghsm_receipt *r;
	struct ghsm_map *m;
	unsigned long flags;
	int ret;

	mutex_lock(&ghsm_lock);
	spin_lock_irqsave(&lease->lock, flags);
	r = ghsm_lease_find_locked(lease, id);
	if (!r) {
		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		return -ENOENT; /* unknown is never a completion ack */
	}
	if (r->completed) {
		list_del(&r->node);
		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		kfree(r);
		return 0;
	}
	if (r->reclaiming || !r->map) {
		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		return -EAGAIN;
	}
	m = r->map;
	if (m->reset_failed) {
		spin_unlock_irqrestore(&lease->lock, flags);
		mutex_unlock(&ghsm_lock);
		return -EIO;
	}
	if (r->stalled) {
		WARN_ON(!ghsm_lease_core_retry(&lease->core));
		r->stalled = false;
	}
	r->reclaiming = true;
	m->dying = true;
	m->retries = 0;
	list_del_init(&m->node);
	spin_unlock_irqrestore(&lease->lock, flags);
	mutex_unlock(&ghsm_lock);
	ret = ghsm_try_destroy(m);
	if (ret) {
		mutex_lock(&ghsm_lock);
		list_add_tail(&m->node, &ghsm_maps);
		ghsm_lease_requeued(m);
		mutex_unlock(&ghsm_lock);
		ghsm_lease_schedule_reaper();
		return ret;
	}
	/* The local reclaim really completed. Another ack may already consume
	 * the receipt, so find it again rather than reuse an old pointer. */
	spin_lock_irqsave(&lease->lock, flags);
	r = ghsm_lease_find_locked(lease, id);
	if (r && r->completed)
		list_del(&r->node);
	else
		r = NULL;
	spin_unlock_irqrestore(&lease->lock, flags);
	kfree(r);
	return 0;
}

static long ghsm_lease_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ghsm_lease *lease = file->private_data;
	unsigned long flags;

	switch (cmd) {
	case GHSM_SEAL_VM_LEASE:
		return ghsm_lease_seal(lease);
	case GHSM_QUERY_VM_LEASE: {
		struct ghsm_vm_lease_status status;

		spin_lock_irqsave(&lease->lock, flags);
		status.version = GHSM_LEASE_ABI_VERSION;
		status.state = ghsm_lease_core_state(&lease->core);
		status.generation = lease->generation;
		status.owned_maps = lease->core.owned_maps;
		status.inflight_shares = lease->core.inflight_shares;
		status.last_errno = lease->core.last_errno;
		spin_unlock_irqrestore(&lease->lock, flags);
		return copy_to_user((void __user *)arg, &status, sizeof(status)) ? -EFAULT : 0;
	}
	case GHSM_UNSHARE_LEASE_PARCEL: {
		struct ghsm_unshare_lease_parcel request;

		if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
			return -EFAULT;
		return ghsm_lease_unshare(lease, request.parcel_id);
	}
	default:
		return -ENOTTY;
	}
}

static __poll_t ghsm_lease_poll(struct file *file, poll_table *wait)
{
	struct ghsm_lease *lease = file->private_data;
	unsigned long flags;
	u32 state;

	poll_wait(file, &lease->wait, wait);
	spin_lock_irqsave(&lease->lock, flags);
	state = ghsm_lease_core_state(&lease->core);
	spin_unlock_irqrestore(&lease->lock, flags);
	if (state == GHSM_LEASE_COMPLETE)
		return EPOLLIN | EPOLLRDNORM;
	if (state == GHSM_LEASE_STALLED)
		return EPOLLERR;
	return 0;
}

static int ghsm_lease_file_release(struct inode *inode, struct file *file)
{
	struct ghsm_lease *lease = file->private_data;

	(void)inode;
	ghsm_lease_seal(lease);
	kref_put(&lease->refs, ghsm_lease_release_ref);
	return 0;
}

static const struct file_operations ghsm_lease_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ghsm_lease_ioctl,
	.compat_ioctl = ghsm_lease_ioctl,
	.poll = ghsm_lease_poll,
	.release = ghsm_lease_file_release,
};

static int ghsm_open_vm_lease(int vm_fd)
{
	struct file *vm_file = NULL;
	struct ghsm_lease *lease;
	void *ghvm;
	int fd;

	ghvm = ghsm_get_ghvm(vm_fd, &vm_file);
	if (!ghvm)
		return -EINVAL;
	lease = kzalloc(sizeof(*lease), GFP_KERNEL);
	if (!lease) {
		fput(vm_file);
		return -ENOMEM;
	}
	kref_init(&lease->refs);
	spin_lock_init(&lease->lock);
	INIT_LIST_HEAD(&lease->receipts);
	init_waitqueue_head(&lease->wait);
	lease->vm_file = vm_file; /* exact OPEN VM identity, no post-seal VM ref */
	__module_get(THIS_MODULE); /* maps keep code alive even after fd release */
	mutex_lock(&ghsm_lock);
	if (ghsm_lease_generation == U64_MAX) {
		mutex_unlock(&ghsm_lock);
		kref_put(&lease->refs, ghsm_lease_release_ref);
		return -EOVERFLOW;
	}
	lease->generation = ++ghsm_lease_generation;
	mutex_unlock(&ghsm_lock);
	fd = anon_inode_getfd("gunyah-share-lease", &ghsm_lease_fops, lease,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0)
		kref_put(&lease->refs, ghsm_lease_release_ref);
	return fd;
}

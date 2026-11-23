// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <limits>
#include <mutex>
#include <utility>

namespace android_display {

// Shared by all planes in one VMM. Zero is reserved for an explicit new binding;
// exhausted identities never wrap into an earlier, still replayable identity.
class SurfaceAttachmentIds {
public:
    explicit SurfaceAttachmentIds(int64_t first = 1) : mNext(first) {}

    int64_t allocate() {
        auto next = mNext.load(std::memory_order_relaxed);
        while (next > 0) {
            const auto after = next == std::numeric_limits<int64_t>::max() ? 0 : next + 1;
            if (mNext.compare_exchange_weak(next, after, std::memory_order_relaxed)) return next;
        }
        return 0;
    }

private:
    std::atomic<int64_t> mNext;
};

// Metadata only; the caller holds the same surface mutex while checking this
// identity and replacing or clearing its native window.
class SurfaceAttachmentOwner {
public:
    bool matches(int64_t owner) const { return owner > 0 && owner == mOwner; }
    void claim(int64_t owner) { mOwner = owner > 0 ? owner : 0; }
    void release() { mOwner = 0; }

private:
    int64_t mOwner = 0;
};

// A context clears its callback before destroying the objects captured by it.
// Clearing waits for current invocations; future callers never retain a copied
// callable that can outlive that context. Callbacks do not call set() themselves.
template <typename ResultType>
class SerializedDisplayReplay {
public:
    using Callback = std::function<ResultType(bool, int64_t)>;

    void set(Callback callback) {
        std::lock_guard lock(mMutex);
        mCallback = std::move(callback);
    }

    ResultType invoke(bool forCursor, int64_t session) {
        std::lock_guard lock(mMutex);
        return mCallback ? mCallback(forCursor, session) : ResultType{};
    }

private:
    std::mutex mMutex;
    Callback mCallback;
};

}  // namespace android_display

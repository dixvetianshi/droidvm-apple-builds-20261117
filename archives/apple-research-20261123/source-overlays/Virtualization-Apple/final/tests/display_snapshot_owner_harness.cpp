// Bounded regression harness over the actual production owner (generated include).
// These platform doubles expose post-time mapping reuse and producer switching;
// they do not validate Android BufferQueue, binder transport or Vulkan drivers.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <vector>

struct ErrorInfo {
    std::string text;
    template <class T> ErrorInfo& operator<<(const T& value) {
        std::ostringstream stream;
        stream << value;
        text += stream.str();
        return *this;
    }
    const std::string& message() const { return text; }
};
static std::ostream& operator<<(std::ostream& stream, const ErrorInfo& error) {
    return stream << error.text;
}
static ErrorInfo Error() { return {}; }
template <class T> class Result {
public:
    Result(T value) : mValue(value) {}
    Result(const ErrorInfo& error) : mError(error) {}
    bool ok() const { return mValue.has_value(); }
    const ErrorInfo& error() const { return mError; }
    T& operator*() { return *mValue; }
private:
    std::optional<T> mValue;
    ErrorInfo mError;
};
template <> class Result<void> {
public:
    Result() = default;
    Result(const ErrorInfo& error) : mOk(false), mError(error) {}
    bool ok() const { return mOk; }
    const ErrorInfo& error() const { return mError; }
private:
    bool mOk = true;
    ErrorInfo mError;
};
namespace android::base {
template <class F> class ScopeGuard {
public:
    explicit ScopeGuard(F callback) : mCallback(std::move(callback)) {}
    ~ScopeGuard() { if (mEnabled) mCallback(); }
    void Disable() { mEnabled = false; }
private:
    F mCallback;
    bool mEnabled = true;
};
template <class F> ScopeGuard<F> make_scope_guard(F callback) {
    return ScopeGuard<F>(std::move(callback));
}
}
struct NullLog {
    template <class T> NullLog& operator<<(const T&) { return *this; }
};
#define LOG(level) NullLog{}
#define PLOG(level) NullLog{}
struct ScopedTrace { explicit ScopedTrace(const char*) {} };
static bool envFlagEnabled(const char*, bool defaultValue) { return defaultValue; }
static bool isSurfaceUnavailableStatus(int status) { return status == -ENODEV || status == -EINVAL; }
enum class RuntimeFlipFailureStage { kDequeue, kTargetImport, kSubmit, kQueue };
static bool injectRuntimeFlipFailure(RuntimeFlipFailureStage) { return false; }

constexpr int HAL_PIXEL_FORMAT_RGBA_8888 = 1;
constexpr int NATIVE_WINDOW_API_EGL = 1;
constexpr int NATIVE_WINDOW_API_CPU = 2;
constexpr int NATIVE_WINDOW_SET_DEQUEUE_TIMEOUT = 1;
constexpr uint64_t AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE = 0x100;
constexpr uint64_t AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER = 0x200;
constexpr uint64_t AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY = 0x800;
struct ANativeWindow_Buffer {
    int32_t width = 0, height = 0, stride = 0, format = 0;
    void* bits = nullptr;
};
struct ANativeWindow;
struct AHardwareBuffer { ANativeWindow* owner = nullptr; };
struct ANativeWindowBuffer { AHardwareBuffer hardware; };
struct ANativeWindow {
    int (*perform)(ANativeWindow*, int, int64_t) = nullptr;
    int width = 0, height = 0, stride = 0, format = 0;
    uint64_t usage = 0;
    int api = 0, transform = 0;
    int64_t timeout = -1;
    bool locked = false, wrongLockDimensions = false;
    int lockStatus = 0, postStatus = 0, dequeueStatus = 0, queueStatus = 0;
    int lockCalls = 0, unlockCalls = 0, cpuPosts = 0, gpuQueues = 0;
    int controlSubmissions = 0;
    std::vector<uint32_t> pixels, lastPosted;
    ANativeWindowBuffer buffer{{this}};
    ANativeWindow() {
        perform = [](ANativeWindow* window, int, int64_t timeout) {
            window->timeout = timeout;
            return 0;
        };
    }
};
static std::vector<uint32_t> visiblePixels(const ANativeWindow& window) {
    std::vector<uint32_t> result;
    for (int y = 0; y < window.height; ++y) {
        const auto* row = window.pixels.data() + y * window.stride;
        result.insert(result.end(), row, row + window.width);
    }
    return result;
}
static int native_window_api_connect(ANativeWindow* window, int api) {
    if (window->api != 0) return -EBUSY;
    window->api = api;
    return 0;
}
static int native_window_api_disconnect(ANativeWindow* window, int) {
    window->api = 0;
    window->usage = 0;
    window->transform = 0;
    window->timeout = -1;
    return 0;
}
static int ANativeWindow_setBuffersGeometry(ANativeWindow* window, int width, int height, int format) {
    window->width = width;
    window->height = height;
    window->stride = width + 2; // Deliberate native padding.
    window->format = format;
    window->pixels.resize(static_cast<size_t>(window->stride) * height);
    return 0;
}
static int ANativeWindow_setBuffersTransform(ANativeWindow* window, int transform) {
    window->transform = transform;
    return 0;
}
static int ANativeWindow_setUsage(ANativeWindow* window, uint64_t usage) {
    window->usage = usage;
    return 0;
}
static int ANativeWindow_lock(ANativeWindow* window, ANativeWindow_Buffer* buffer, void*) {
    ++window->lockCalls;
    if (window->lockStatus != 0) return window->lockStatus;
    if (window->locked) return -EBUSY;
    window->locked = true;
    *buffer = {window->width + (window->wrongLockDimensions ? 1 : 0), window->height,
               window->stride, window->format, window->pixels.data()};
    return 0;
}
static int ANativeWindow_unlockAndPost(ANativeWindow* window) {
    ++window->unlockCalls;
    if (!window->locked) return -EINVAL;
    window->locked = false;
    window->lastPosted = visiblePixels(*window);
    ++window->cpuPosts;
    // Simulate an immediately recycled gralloc mapping. Any later read is wrong.
    std::fill(window->pixels.begin(), window->pixels.end(), 0xdeadbeefU);
    return window->postStatus;
}
static int ANativeWindow_dequeueBuffer(ANativeWindow* window, ANativeWindowBuffer** buffer, int* fd) {
    *fd = -1;
    if (window->dequeueStatus != 0) return window->dequeueStatus;
    *buffer = &window->buffer;
    return 0;
}
static int ANativeWindow_cancelBuffer(ANativeWindow*, ANativeWindowBuffer*, int fd) {
    if (fd >= 0) close(fd);
    return 0;
}
static int ANativeWindow_queueBuffer(ANativeWindow* window, ANativeWindowBuffer*, int fd) {
    if (fd >= 0) close(fd); // The native API consumes the fd even on failure.
    if (window->queueStatus != 0) return window->queueStatus;
    window->lastPosted = visiblePixels(*window);
    ++window->gpuQueues;
    return 0;
}
static AHardwareBuffer* ANativeWindowBuffer_getHardwareBuffer(ANativeWindowBuffer* buffer) {
    return &buffer->hardware;
}
struct Surface {
    ANativeWindow* window;
    explicit Surface(ANativeWindow* value) : window(value) {}
    ANativeWindow* get() { return window; }
    ANativeWindow* release() { return std::exchange(window, nullptr); }
};
struct ASurfaceControl { ANativeWindow* window; };
struct ASurfaceTransaction { ASurfaceControl* control = nullptr; AHardwareBuffer* buffer = nullptr; };
struct SurfaceControl {
    bool supported = false;
    int transactionsCreated = 0, transactionsDeleted = 0;
    static SurfaceControl& GetInstance() { static SurfaceControl instance; return instance; }
    bool IsSupported() const { return supported; }
    ASurfaceControl* ASurfaceControl_createFromWindow(ANativeWindow* window, const char*) {
        return new ASurfaceControl{window};
    }
    void ASurfaceControl_release(ASurfaceControl* control) { delete control; }
    ASurfaceTransaction* ASurfaceTransaction_create() {
        ++transactionsCreated;
        return new ASurfaceTransaction;
    }
    void ASurfaceTransaction_setBuffer(ASurfaceTransaction* transaction, ASurfaceControl* control,
                                      AHardwareBuffer* buffer, int) {
        transaction->control = control;
        transaction->buffer = buffer;
    }
    void ASurfaceTransaction_setBufferTransform(ASurfaceTransaction*, ASurfaceControl*, int) {}
    void ASurfaceTransaction_apply(ASurfaceTransaction* transaction) {
        ++transaction->control->window->controlSubmissions;
    }
    void ASurfaceTransaction_delete(ASurfaceTransaction* transaction) {
        ++transactionsDeleted;
        delete transaction;
    }
};
struct VulkanDisplayBridge {
    int blits = 0, resets = 0, lastCompletionFd = -1;
    int64_t lastImport = 0;
    uint32_t color = 0x12345678U;
    bool failBlit = false, emitFence = false;
    bool canImportAcquireFence() const { return true; }
    Result<void> resetTargetsForSurfaceChange() { ++resets; return {}; }
    Result<int> blit(int64_t import, AHardwareBuffer* target, int fd, bool) {
        if (fd >= 0) close(fd);
        if (failBlit) return Error() << "fixture blit failure";
        ++blits;
        lastImport = import;
        std::fill(target->owner->pixels.begin(), target->owner->pixels.end(), color);
        if (!emitFence) return -1;
        int pipeFds[2];
        if (pipe(pipeFds) != 0) return Error() << "fixture pipe failure";
        const char signal = 1;
        write(pipeFds[1], &signal, 1);
        close(pipeFds[1]);
        lastCompletionFd = pipeFds[0];
        return lastCompletionFd;
    }
};

#include "display_owner_under_test.inc"

static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template <class T> static void requireOk(const Result<T>& result) {
    if (!result.ok()) throw std::runtime_error(result.error().message());
}
static void attach(AndroidDisplaySurface& surface, ANativeWindow& window) {
    Surface binderSurface(&window);
    requireOk(surface.setNativeSurface(&binderSurface));
}
static std::vector<uint32_t> pattern(int width, int height, uint32_t seed) {
    std::vector<uint32_t> result;
    for (int i = 0; i < width * height; ++i) result.push_back(seed + i * 0x01030507U);
    return result;
}
static void writeCpu(ANativeWindow_Buffer& buffer, const std::vector<uint32_t>& pixels) {
    auto* target = static_cast<uint32_t*>(buffer.bits);
    for (int y = 0; y < buffer.height; ++y) {
        std::copy_n(pixels.data() + y * buffer.width, buffer.width, target + y * buffer.stride);
    }
}
static void submitCpu(AndroidDisplaySurface& surface, const std::vector<uint32_t>& pixels) {
    ANativeWindow_Buffer buffer;
    requireOk(surface.lock(&buffer));
    writeCpu(buffer, pixels);
    requireOk(surface.unlockAndPost());
}
static Result<int> replay(AndroidDisplaySurface& surface, VulkanDisplayBridge* bridge = nullptr) {
#ifdef OWNER_LEGACY
    if (surface.hasSavedFrame()) {
        if (auto result = surface.drawSavedFrame(); !result.ok()) return result.error();
        return -1;
    }
    if (bridge && surface.lastFlipImport()) return surface.flip(*bridge, surface.lastFlipImport());
    return -1;
#else
    return surface.replayFrame(bridge);
#endif
}
static void closeCompletion(Result<int>& result) {
    requireOk(result);
    if (*result >= 0) close(*result);
}

int main() {
    int passes = 0, failures = 0;
    auto test = [&](const char* name, auto callback) {
        try {
            callback();
            ++passes;
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cout << "FAIL " << name << ": " << error.what() << '\n';
        }
    };
    test("post_reuse_stride_and_same_geometry", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        requireOk(surface.configure(3, 2));
        attach(surface, first);
        const auto frame = pattern(3, 2, 0x11223344U);
        submitCpu(surface, frame);
        require(first.lastPosted == frame, "native stride copy differs");
        requireOk(surface.saveFrame());
        requireOk(surface.configure(3, 2));
        surface.removeSurface();
        attach(surface, second);
        auto result = replay(surface);
        closeCompletion(result);
        require(second.lastPosted == frame, "replay read a recycled mapping or lost same geometry pixels");
    });
    test("save_during_borrow_keeps_previous_submission", [] {
        AndroidDisplaySurface surface("cursor");
        ANativeWindow first, second;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        const auto oldFrame = pattern(2, 2, 0x01020304U);
        const auto newFrame = pattern(2, 2, 0xa1b2c3d4U);
        submitCpu(surface, oldFrame);
        ANativeWindow_Buffer pending;
        requireOk(surface.lock(&pending));
        writeCpu(pending, newFrame);
        requireOk(surface.saveFrame());
        surface.removeSurface();
        attach(surface, second);
        auto result = replay(surface);
        closeCompletion(result);
        require(second.lastPosted == oldFrame, "save captured an unfinished borrow");
        requireOk(surface.unlockAndPost());
        require(second.lastPosted == newFrame, "borrow did not follow current window at post");
    });
    test("window_replaced_during_cpu_borrow", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        ANativeWindow_Buffer buffer;
        requireOk(surface.lock(&buffer));
        const auto frame = pattern(2, 2, 0x22334455U);
        writeCpu(buffer, frame);
        surface.removeSurface();
        attach(surface, second);
        requireOk(surface.unlockAndPost());
        require(first.cpuPosts == 0 && !first.locked, "old window retained a borrowed mapping");
        require(second.lastPosted == frame, "post unlocked or copied the wrong window");
    });
    test("geometry_change_invalidates_cpu_replay", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        submitCpu(surface, pattern(2, 2, 0x44556677U));
        requireOk(surface.saveFrame());
        requireOk(surface.configure(4, 3));
        surface.removeSurface();
        attach(surface, second);
        auto result = replay(surface);
        closeCompletion(result);
        require(second.cpuPosts == 0, "old geometry was marked replayable");
        const auto frame = pattern(4, 3, 0x778899aaU);
        submitCpu(surface, frame);
        require(second.lastPosted == frame, "new geometry staging metadata differs");
    });
    test("cpu_gpu_cpu_latest_and_gpu_usage", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, gpuWindow, cpuWindow;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        submitCpu(surface, pattern(2, 2, 0x11223344U));
        requireOk(surface.saveFrame());
        auto gpu = surface.flip(bridge, 71);
        closeCompletion(gpu);
        surface.removeSurface();
        attach(surface, gpuWindow);
        auto result = replay(surface, &bridge);
        closeCompletion(result);
        require(gpuWindow.gpuQueues == 1 && gpuWindow.cpuPosts == 0, "old CPU snapshot won over GPU");
        require(gpuWindow.usage == 0xb00 && gpuWindow.api == NATIVE_WINDOW_API_EGL,
                "GPU replay changed producer usage");
        require(gpuWindow.timeout == 0, "GPU replay lost zero dequeue timeout");
        const auto frame = pattern(2, 2, 0x99aabbccU);
        submitCpu(surface, frame);
        requireOk(surface.saveFrame());
        surface.removeSurface();
        attach(surface, cpuWindow);
        const int blitsBefore = bridge.blits;
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(cpuWindow.lastPosted == frame && bridge.blits == blitsBefore, "old GPU import won over CPU");
    });
    test("gpu_background_and_panel_drop_keep_latest_import", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second, third;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        submitCpu(surface, pattern(2, 2, 0x11223344U));
        requireOk(surface.saveFrame());
        surface.removeSurface();
        auto result = surface.flip(bridge, 81);
        closeCompletion(result);
        attach(surface, second);
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(second.gpuQueues == 1 && bridge.lastImport == 81, "background GPU did not supersede CPU");
        second.dequeueStatus = -ETIMEDOUT;
        result = surface.flip(bridge, 82);
        closeCompletion(result);
        surface.removeSurface();
        attach(surface, third);
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(third.gpuQueues == 1 && bridge.lastImport == 82, "panel drop lost latest accepted source");
    });
    test("gpu_import_release_and_geometry_expire_replay", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        auto result = surface.flip(bridge, 91);
        closeCompletion(result);
        surface.forgetFlipImport(91);
        surface.removeSurface();
        attach(surface, second);
        const int before = bridge.blits;
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(bridge.blits == before, "released GPU import was replayed");
        result = surface.flip(bridge, 92);
        closeCompletion(result);
        requireOk(surface.configure(4, 3));
        const int after = bridge.blits;
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(bridge.blits == after, "old geometry GPU import was replayed");
    });
    test("failed_gpu_keeps_cpu_replay", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        const auto frame = pattern(2, 2, 0x11223344U);
        submitCpu(surface, frame);
        requireOk(surface.saveFrame());
        bridge.failBlit = true;
        auto failed = surface.flip(bridge, 101);
        require(!failed.ok(), "fixture GPU failure was not surfaced");
        surface.removeSurface();
        attach(surface, second);
        auto result = replay(surface, &bridge);
        closeCompletion(result);
        require(second.lastPosted == frame, "failed GPU invalidated the last accepted CPU source");
    });
    test("copy_failure_returns_native_window", [] {
        AndroidDisplaySurface surface("cursor");
        ANativeWindow first, second;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        const auto frame = pattern(2, 2, 0x11223344U);
        submitCpu(surface, frame);
        requireOk(surface.saveFrame());
        surface.removeSurface();
        second.wrongLockDimensions = true;
        attach(surface, second);
        auto result = replay(surface);
        require(!result.ok(), "fixture geometry mismatch was not surfaced");
        require(!second.locked && second.unlockCalls == 1, "copy error leaked a locked native window");
        second.wrongLockDimensions = false;
        result = replay(surface);
        closeCompletion(result);
        require(second.lastPosted == frame, "copy error lost the owned replay pixels");
    });
    test("post_without_borrow_does_not_resurrect_cpu", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        submitCpu(surface, pattern(2, 2, 0x11223344U));
        requireOk(surface.saveFrame());
        auto result = surface.flip(bridge, 111);
        closeCompletion(result);
        requireOk(surface.unlockAndPost());
        surface.removeSurface();
        attach(surface, second);
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(second.gpuQueues == 1 && second.cpuPosts == 0, "empty post resurrected old CPU state");
    });
    test("cpu_background_snapshot_and_cursor_independence", [] {
        AndroidDisplaySurface scanout("scanout"), cursor("cursor");
        ANativeWindow mainWindow, cursorWindow;
        VulkanDisplayBridge bridge;
        requireOk(scanout.configure(3, 2));
        requireOk(cursor.configure(2, 2));
        const auto cursorFrame = pattern(2, 2, 0x33445566U);
        submitCpu(cursor, cursorFrame);
        auto result = scanout.flip(bridge, 121);
        closeCompletion(result);
        attach(scanout, mainWindow);
        attach(cursor, cursorWindow);
        result = replay(scanout, &bridge);
        closeCompletion(result);
        result = replay(cursor, &bridge);
        closeCompletion(result);
        require(mainWindow.gpuQueues == 1, "main GPU source missing");
        require(cursorWindow.lastPosted == cursorFrame && cursorWindow.cpuPosts == 1,
                "cursor CPU snapshot was coupled to main GPU state");
    });
    test("gpu_completion_fd_ownership", [] {
        AndroidDisplaySurface surface("scanout");
        ANativeWindow window;
        VulkanDisplayBridge bridge;
        bridge.emitFence = true;
        requireOk(surface.configure(2, 2));
        attach(surface, window);
        auto result = surface.flip(bridge, 131);
        requireOk(result);
        require(*result >= 0 && fcntl(*result, F_GETFD) >= 0, "source completion fd was consumed early");
        require(fcntl(bridge.lastCompletionFd, F_GETFD) < 0 && errno == EBADF,
                "queue did not consume target completion fd");
        close(*result);
        window.queueStatus = -EIO;
        result = surface.flip(bridge, 132);
        require(!result.ok(), "fixture queue failure was not surfaced");
        require(fcntl(bridge.lastCompletionFd, F_GETFD) < 0 && errno == EBADF,
                "failed queue leaked target completion fd");
    });
    test("surface_control_submission_expires_older_cpu_and_gpu", [] {
        auto& control = SurfaceControl::GetInstance();
        control.supported = true;
        auto restore = android::base::make_scope_guard([&control] { control.supported = false; });
        AndroidDisplaySurface surface("scanout");
        ANativeWindow first, second, third;
        VulkanDisplayBridge bridge;
        requireOk(surface.configure(2, 2));
        attach(surface, first);
        submitCpu(surface, pattern(2, 2, 0x11223344U));
        requireOk(surface.saveFrame());
        AHardwareBuffer external{&first};
        requireOk(surface.setBuffer(&external));
        require(first.controlSubmissions == 1, "SurfaceControl submission was not called");
        surface.removeSurface();
        attach(surface, second);
        auto result = replay(surface, &bridge);
        closeCompletion(result);
        require(second.cpuPosts == 0 && second.gpuQueues == 0, "old CPU replay replaced SurfaceControl source");
        result = surface.flip(bridge, 141);
        closeCompletion(result);
        requireOk(surface.setBuffer(&external));
        surface.removeSurface();
        attach(surface, third);
        const int before = bridge.blits;
        result = replay(surface, &bridge);
        closeCompletion(result);
        require(bridge.blits == before && third.cpuPosts == 0 && third.gpuQueues == 0,
                "old GPU replay replaced SurfaceControl source");
        surface.removeSurface();
    });
    test("missing_surface_control_does_not_allocate_transaction", [] {
        auto& control = SurfaceControl::GetInstance();
        control.supported = true;
        auto restore = android::base::make_scope_guard([&control] { control.supported = false; });
        AndroidDisplaySurface surface("scanout");
        ANativeWindow window;
        AHardwareBuffer external{&window};
        const int created = control.transactionsCreated;
        const auto result = surface.setBuffer(&external);
        require(!result.ok(), "missing control submission was accepted");
        require(control.transactionsCreated == created, "missing control allocated and leaked a transaction");
    });
    std::cout << "SUMMARY pass=" << passes << " fail=" << failures << '\n';
    return failures ? 1 : 0;
}

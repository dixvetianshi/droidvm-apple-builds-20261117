/*
 * One-process iPadOS diagnostic. No PID discovery, persistence or RAM changes.
 *
 * ABI sources: apple-oss-distributions/xnu, commit
 * ac9718fb1af618d5ce8678d0dc6e8a58f252216f (the guest's XNU pin):
 * bsd/sys/proc_info.h, lines 59-82, 729-730 and 753-755;
 * libsyscall/wrappers/libproc/libproc.h, lines 96 and 102;
 * bsd/sys/kern_memorystatus.h, lines 333, 344-345 and 482-495.
 * The private SDK headers are optional; their exact public XNU layouts below
 * have fixed size/offset assertions. No direct syscall-number fallback is used.
 */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__arm64e__)
#error "Build only for arm64e-apple-ios27.0 with the real iPhoneOS SDK"
#endif

#if __has_include(<sys/proc_info.h>)
#include <sys/proc_info.h>
typedef struct proc_bsdinfo probe_bsdinfo;
#define PROBE_PROC_INFO_SOURCE "SDK header, checked against pinned XNU"
#else
typedef struct {
    uint32_t pbi_flags, pbi_status, pbi_xstatus, pbi_pid, pbi_ppid;
    uint32_t pbi_uid, pbi_gid, pbi_ruid, pbi_rgid, pbi_svuid, pbi_svgid;
    uint32_t rfu_1;
    char pbi_comm[16];
    char pbi_name[32];
    uint32_t pbi_nfiles, pbi_pgid, pbi_pjobc, e_tdev, e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec, pbi_start_tvusec;
} probe_bsdinfo;
#define PROC_PIDTBSDINFO 3
#define PROC_PIDPATHINFO_MAXSIZE 4096
#define PROBE_PROC_INFO_SOURCE "pinned public XNU minimal layout"
#endif

#if __has_include(<libproc.h>)
#include <libproc.h>
#else
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer,
                       int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
#endif

#if __has_include(<sys/kern_memorystatus.h>)
#include <sys/kern_memorystatus.h>
typedef memorystatus_memlimit_properties_t probe_limits;
#define PROBE_MEMLIMIT_SOURCE "SDK header, checked against pinned XNU"
#else
typedef struct {
    int32_t memlimit_active;
    uint32_t memlimit_active_attr;
    int32_t memlimit_inactive;
    uint32_t memlimit_inactive_attr;
} probe_limits;
#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES 8
#define MEMORYSTATUS_MEMLIMIT_ATTR_FATAL 1U
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
                               void *buffer, size_t buffersize);
#define PROBE_MEMLIMIT_SOURCE "pinned public XNU minimal layout"
#endif

_Static_assert(sizeof(void *) == 8 && sizeof(pid_t) == 4 && sizeof(uid_t) == 4,
               "Darwin arm64 process scalar ABI");
_Static_assert(PROC_PIDTBSDINFO == 3 && PROC_PIDPATHINFO_MAXSIZE == 4096,
               "pinned libproc flavors");
_Static_assert(sizeof(probe_bsdinfo) == 136, "proc_bsdinfo size");
_Static_assert(offsetof(probe_bsdinfo, pbi_pid) == 12, "pbi_pid offset");
_Static_assert(offsetof(probe_bsdinfo, pbi_uid) == 20, "pbi_uid offset");
_Static_assert(offsetof(probe_bsdinfo, pbi_comm) == 48, "pbi_comm offset");
_Static_assert(sizeof(((probe_bsdinfo *)0)->pbi_comm) == 16, "pbi_comm size");
_Static_assert(offsetof(probe_bsdinfo, pbi_name) == 64, "pbi_name offset");
_Static_assert(sizeof(((probe_bsdinfo *)0)->pbi_name) == 32, "pbi_name size");
_Static_assert(offsetof(probe_bsdinfo, pbi_start_tvsec) == 120, "start_sec offset");
_Static_assert(offsetof(probe_bsdinfo, pbi_start_tvusec) == 128, "start_usec offset");
_Static_assert(sizeof(probe_limits) == 16, "memlimit v1 size");
_Static_assert(offsetof(probe_limits, memlimit_active) == 0, "active offset");
_Static_assert(offsetof(probe_limits, memlimit_active_attr) == 4, "active attr offset");
_Static_assert(offsetof(probe_limits, memlimit_inactive) == 8, "inactive offset");
_Static_assert(offsetof(probe_limits, memlimit_inactive_attr) == 12, "inactive attr offset");
_Static_assert(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES == 7 &&
               MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES == 8 &&
               MEMORYSTATUS_MEMLIMIT_ATTR_FATAL == 1U, "pinned memlimit commands");

struct identity {
    bool has_bsd, has_path, target_matches;
    uint32_t pid, uid, real_uid;
    uint64_t start_sec, start_usec;
    char comm[17], registered_name[33], path[PROC_PIDPATHINFO_MAXSIZE];
};

struct report {
    const char *verb, *error_stage, *error_reason;
    int pid, error_number, exit_code;
    uint64_t expected_sec, expected_usec;
    bool has_expected, has_before, has_after, ok, write_attempted;
    bool set_returned_success, idempotent;
    int32_t desired;
    struct identity first, before_write, after_write, final;
    probe_limits before, after;
};

static const char *identity_name(const struct identity *value) {
    return value->registered_name[0] ? value->registered_name : value->comm;
}

static int read_identity(int pid, struct identity *out, const char **reason) {
    probe_bsdinfo value = {0};
    errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, (int)sizeof(value));
    if (count != (int)sizeof(value)) {
        *reason = "proc_pidinfo did not return the complete pinned BSD identity";
        return count <= 0 && errno ? errno : EIO;
    }
    out->has_bsd = true;
    out->pid = value.pbi_pid;
    out->uid = value.pbi_uid;
    out->real_uid = value.pbi_ruid;
    out->start_sec = value.pbi_start_tvsec;
    out->start_usec = value.pbi_start_tvusec;
    if (!memchr(value.pbi_comm, 0, sizeof(value.pbi_comm)) ||
        !memchr(value.pbi_name, 0, sizeof(value.pbi_name))) {
        *reason = "BSD name fields are not terminated";
        return EOVERFLOW;
    }
    memcpy(out->comm, value.pbi_comm, sizeof(value.pbi_comm));
    memcpy(out->registered_name, value.pbi_name, sizeof(value.pbi_name));
    errno = 0;
    count = proc_pidpath(pid, out->path, (uint32_t)sizeof(out->path));
    if (count <= 0 || count >= (int)sizeof(out->path) ||
        !memchr(out->path, 0, sizeof(out->path))) {
        *reason = "proc_pidpath did not return a complete executable path";
        return count <= 0 && errno ? errno : EOVERFLOW;
    }
    out->has_path = true;
    /* pbi_name may be empty: proc_info.h explicitly documents that case. */
    if (out->pid != (uint32_t)pid || out->uid != 501 ||
        out->start_usec > 999999 || strcmp(out->comm, "lsd") ||
        strcmp(identity_name(out), "lsd") || strcmp(out->path, "/usr/libexec/lsd")) {
        *reason = "Only UID 501, name lsd, executable /usr/libexec/lsd is accepted";
        return EINVAL;
    }
    out->target_matches = true;
    return 0;
}

static bool same_identity(const struct identity *left, const struct identity *right) {
    return left->target_matches && right->target_matches &&
           left->pid == right->pid && left->uid == right->uid &&
           left->start_sec == right->start_sec && left->start_usec == right->start_usec &&
           !strcmp(identity_name(left), identity_name(right)) &&
           !strcmp(left->path, right->path);
}

static int get_limits(int pid, probe_limits *out) {
    memset(out, 0, sizeof(*out));
    errno = 0;
    int result = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES,
                                     (int32_t)pid, 0, out, sizeof(*out));
    return result == 0 ? 0 : (errno ? errno : EIO);
}

static bool unchanged_other_limits(const probe_limits *before, const probe_limits *after) {
    return before->memlimit_active_attr == after->memlimit_active_attr &&
           before->memlimit_inactive == after->memlimit_inactive &&
           before->memlimit_inactive_attr == after->memlimit_inactive_attr;
}

static bool decimal(const char *text, uint64_t maximum, uint64_t *out) {
    uint64_t value = 0;
    if (!text || !*text) return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9' || value > (maximum - (uint64_t)(*p - '0')) / 10)
            return false;
        value = value * 10 + (uint64_t)(*p - '0');
    }
    *out = value;
    return true;
}

static void json_string(const char *text) {
    if (!text) { fputs("null", stdout); return; }
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32 || *p > 126) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static const char *boolean(bool value) { return value ? "true" : "false"; }

static void print_identity(const struct identity *value) {
    if (!value->has_bsd) { fputs("null", stdout); return; }
    printf("{\"pid\":%" PRIu32 ",\"uid\":%" PRIu32 ",\"real_uid\":%" PRIu32
           ",\"start_sec\":%" PRIu64 ",\"start_usec\":%" PRIu64 ",\"name\":",
           value->pid, value->uid, value->real_uid, value->start_sec, value->start_usec);
    json_string(identity_name(value));
    fputs(",\"name_source\":", stdout);
    json_string(value->registered_name[0] ? "pbi_name" : "pbi_comm");
    fputs(",\"comm\":", stdout); json_string(value->comm);
    fputs(",\"path\":", stdout); json_string(value->has_path ? value->path : NULL);
    printf(",\"target_matches\":%s}", boolean(value->target_matches));
}

static void print_limits(const probe_limits *value, bool present) {
    if (!present) { fputs("null", stdout); return; }
    printf("{\"active_mb\":%" PRId32 ",\"active_attr\":%" PRIu32
           ",\"inactive_mb\":%" PRId32 ",\"inactive_attr\":%" PRIu32 "}",
           value->memlimit_active, value->memlimit_active_attr,
           value->memlimit_inactive, value->memlimit_inactive_attr);
}

static int emit(const struct report *r) {
    printf("{\"ok\":%s,\"operation\":", boolean(r->ok)); json_string(r->verb);
    printf(",\"requested_pid\":%d,\"expected_identity\":", r->pid);
    if (r->has_expected)
        printf("{\"start_sec\":%" PRIu64 ",\"start_usec\":%" PRIu64 "}",
               r->expected_sec, r->expected_usec);
    else fputs("null", stdout);
    fputs(",\"identity\":", stdout); print_identity(&r->first);
    fputs(",\"identity_before_write\":", stdout); print_identity(&r->before_write);
    fputs(",\"identity_after_write\":", stdout); print_identity(&r->after_write);
    fputs(",\"identity_after_read\":", stdout); print_identity(&r->final);
    fputs(",\"before\":", stdout); print_limits(&r->before, r->has_before);
    fputs(",\"after\":", stdout); print_limits(&r->after, r->has_after);
    printf(",\"write_attempted\":%s,\"set_returned_success\":%s,\"idempotent\":%s",
           boolean(r->write_attempted), boolean(r->set_returned_success), boolean(r->idempotent));
    fputs(",\"error_stage\":", stdout); json_string(r->error_stage);
    printf(",\"errno\":%d,\"error\":", r->error_number); json_string(r->error_reason);
    fputs(",\"proc_info_contract\":", stdout); json_string(PROBE_PROC_INFO_SOURCE);
    fputs(",\"memlimit_contract\":", stdout); json_string(PROBE_MEMLIMIT_SOURCE);
    fputs(",\"limits_are_observed_effective\":true,\"original_default_sentinel_semantics\":\"unknown\","
          "\"preservation_scope\":\"SET7 preserves the observed inactive value and both attributes; GET8 may expand defaults. "
          "restore16 restores the observed active value, not unknown original default semantics.\","
          "\"identity_atomicity\":\"best effort; the kernel SET7 accepts PID, not the start-time token\","
          "\"persistent_configuration_written\":false,\"total_ram_changed\":false}\n", stdout);
    return ferror(stdout) ? 1 : r->exit_code;
}

int main(int argc, char **argv) {
    struct report r = {0};
    r.verb = argc > 1 ? argv[1] : NULL;
    uint64_t parsed_pid;
    bool inspect = r.verb && !strcmp(r.verb, "inspect");
    bool raise = r.verb && !strcmp(r.verb, "raise64");
    bool restore = r.verb && !strcmp(r.verb, "restore16");
    if ((!inspect && !raise && !restore) || argc != (inspect ? 3 : 5) ||
        !decimal(argv[2], INT_MAX, &parsed_pid) || parsed_pid <= 1 ||
        (!inspect && (!decimal(argv[3], UINT64_MAX, &r.expected_sec) ||
                      !decimal(argv[4], 999999, &r.expected_usec)))) {
        r.error_stage = "arguments"; r.error_number = EINVAL; r.exit_code = 2;
        r.error_reason = "Usage: inspect PID | raise64 PID START_SEC START_USEC | restore16 PID START_SEC START_USEC";
        return emit(&r);
    }
    r.pid = (int)parsed_pid;
    r.has_expected = !inspect;
    r.desired = raise ? 64 : 16;
    const char *reason = NULL;

#define FAIL(stage, number, message) do { \
    r.error_stage = (stage); r.error_number = (number); \
    r.error_reason = (message); r.exit_code = 1; return emit(&r); \
} while (0)
#define READ_ID(field, stage) do { \
    int identity_error = read_identity(r.pid, &r.field, &reason); \
    if (identity_error) FAIL((stage), identity_error, reason); \
} while (0)

    READ_ID(first, "identity_before");
    if (r.has_expected && (r.first.start_sec != r.expected_sec ||
                           r.first.start_usec != r.expected_usec))
        FAIL("expected_identity", ESTALE, "The supplied process start time no longer matches lsd");
    int result = get_limits(r.pid, &r.before);
    if (result) FAIL("get_before", result, "memorystatus GET8 failed");
    r.has_before = true;
    if (inspect) {
        READ_ID(final, "identity_after_read");
        if (!same_identity(&r.first, &r.final))
            FAIL("identity_after_read", ESTALE, "The selected lsd identity changed during GET8");
        r.ok = true;
        return emit(&r);
    }
    if (geteuid() != 0) FAIL("caller_authority", EPERM, "Mutation requires a root caller");
    if (r.before.memlimit_active != r.desired &&
        r.before.memlimit_active != (raise ? 16 : 64))
        FAIL("active_precondition", EINVAL, "Only observed active 16->64 or 64->16 is accepted");

    READ_ID(before_write, "identity_before_write");
    if (!same_identity(&r.first, &r.before_write))
        FAIL("identity_before_write", ESTALE, "The selected lsd identity changed before SET7");
    if (r.before.memlimit_active != r.desired) {
        if ((r.before.memlimit_active_attr | r.before.memlimit_inactive_attr) &
            ~MEMORYSTATUS_MEMLIMIT_ATTR_FATAL)
            FAIL("attribute_precondition", EINVAL, "Attributes are outside the pinned XNU contract");
        probe_limits desired = r.before;
        desired.memlimit_active = r.desired;
        r.write_attempted = true;
        errno = 0;
        result = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES,
                                     (int32_t)r.pid, 0, &desired, sizeof(desired));
        if (result != 0) FAIL("set", errno ? errno : EIO, "memorystatus SET7 failed; no retry or implicit restore");
        r.set_returned_success = true;
        READ_ID(after_write, "identity_after_write");
        if (!same_identity(&r.first, &r.after_write))
            FAIL("identity_after_write", ESTALE, "The selected lsd identity changed after SET7");
    }
    result = get_limits(r.pid, &r.after);
    if (result) FAIL("get_after", result, "memorystatus GET8 after the operation failed");
    r.has_after = true;
    READ_ID(final, "identity_after_read");
    if (!same_identity(&r.first, &r.final))
        FAIL("identity_after_read", ESTALE, "The selected lsd identity changed during the final GET8");
    if (r.after.memlimit_active != r.desired || !unchanged_other_limits(&r.before, &r.after))
        FAIL("verify_after", EIO, "Active limit or preserved observed fields differ on readback");
    r.idempotent = !r.write_attempted;
    r.ok = true;
    return emit(&r);
}

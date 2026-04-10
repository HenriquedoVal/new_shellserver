///
/// Includes

#pragma comment(lib, "advapi32")
#pragma comment(lib, "shlwapi")

// Delayloaded. Deps of libgit2 that we don't use
#pragma comment(lib, "winhttp")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ole32")
#pragma comment(lib, "secur32")


#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <share.h>
#include <wchar.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shlwapi.h>

#include <git2.h>

#define DYNARR_IMPLEMENTATION
#define DYNARR_SCOPE_STATIC
#include "dynarr.h"

#define TERM_IMPLEMENTATION
#include "term.h"

#ifdef NDEBUG
#   define printf(...)
#endif

#include "common.c"


/// Config/Extend

#define GITSTATUS_TIMEOUT 100
#define CMD_DUR_THRESHOLD 200

// I'm using top 17 most used programming languages found somewhere on net
enum {
    HAS_C,
    HAS_CPP,
    HAS_JS,
    HAS_HTML,
    HAS_CSS,
    HAS_PY,
    HAS_TS,
    HAS_JAVA,
    HAS_CSHARP,
    HAS_BASH,
    HAS_PWSH,
    HAS_PHP,
    HAS_GO,
    HAS_RUST,
    HAS_KOTLIN,
    HAS_LUA,
    HAS_ASM,
    EXT_TOTAL
};

#define MAX_EXT_STR_SIZE 4

typedef struct {
    int count;
    char *ext_name[MAX_EXT_STR_SIZE];
} ExtEntry;

static ExtEntry extensions[EXT_TOTAL] = {
    [HAS_C]      = { .count = 2, .ext_name = { "c", "h" }},

    [HAS_CPP]    = { 3, { "cpp", "hh", "hpp"        }},
    [HAS_JS]     = { 3, { "js", "cjs", "mjs"        }},
    [HAS_HTML]   = { 1, { "html"                    }},
    [HAS_CSS]    = { 1, { "css"                     }},
    [HAS_PY]     = { 4, { "py", "pyw", "pyc", "pyd" }},
    [HAS_TS]     = { 1, { "ts"                      }},
    [HAS_JAVA]   = { 1, { "java"                    }},
    [HAS_CSHARP] = { 1, { "cs"                      }},
    [HAS_BASH]   = { 1, { "sh"                      }},
    [HAS_PWSH]   = { 3, { "ps1", "psd1", "psm1"     }},
    [HAS_PHP]    = { 1, { "php"                     }},
    [HAS_GO]     = { 1, { "go"                      }},
    [HAS_RUST]   = { 2, { "rs", "rlib"              }},
    [HAS_KOTLIN] = { 3, { "kt", "ktm", "kts"        }},
    [HAS_LUA]    = { 1, { "lua"                     }},
    [HAS_ASM]    = { 2, { "asm", "s"                }},
};


static char *extmapsign[EXT_TOTAL] = {

                          //   dev | seti | md | custom
    [HAS_C]      = "",   //              󰙱     
    [HAS_CPP]    = "",   //               󰙲     
    [HAS_JS]     = "",   //              󰌞
    [HAS_HTML]   = "",   //              󰌝
    [HAS_CSS]    = "󰌜",   //              󰌜     
    [HAS_PY]     = "",   //              󰌠
    [HAS_TS]     = "",   //              󰛦
    [HAS_JAVA]   = "󰬷",   //              󰬷
    [HAS_CSHARP] = "󰌛",   //               󰌛
    [HAS_BASH]   = "",   //               󱆃
    [HAS_PWSH]   = "󰨊",   //              󰨊
    [HAS_PHP]    = "󰌟",   //              󰌟
    [HAS_GO]     = "",   //              󰟓     
    [HAS_RUST]   = "󱘗",   //              󱘗
    [HAS_KOTLIN] = "󱈙",   //              󱈙     
    [HAS_LUA]    = "󰢱",   //              󰢱
    [HAS_ASM]    = ""    //                     
};


static SetGraphicsRendition extmapcolor[EXT_TOTAL] = {
    [HAS_C]      = SGR_F_BLUE,
    [HAS_CPP]    = SGR_F_BLUE,
    [HAS_JS]     = SGR_F_YELLOW,
    [HAS_HTML]   = SGR_F_RED,
    [HAS_CSS]    = SGR_F_BLUE,
    [HAS_PY]     = SGR_F_YELLOW,
    [HAS_TS]     = SGR_F_BLUE,
    [HAS_JAVA]   = SGR_F_RED,
    [HAS_CSHARP] = SGR_F_BLUE,
    [HAS_BASH]   = SGR_F_WHITE,
    [HAS_PWSH]   = SGR_F_BLUE,
    [HAS_PHP]    = SGR_F_BLUE,
    [HAS_GO]     = SGR_F_BLUE,
    [HAS_RUST]   = SGR_F_RED,
    [HAS_KOTLIN] = SGR_F_GREEN,
    [HAS_LUA]    = SGR_F_BLUE,
    [HAS_ASM]    = SGR_F_WHITE
};


/// Gitstatus thread management

typedef struct {
    char workdir[MAX_PATH];
    HANDLE handle;
} ThreadItem;

static DynArr gitstatus_threads;

static void remove_running_thread_idx(int64_t idx)
{
    ThreadItem *ti = dynarr_at(&gitstatus_threads, idx);
    assert(ti);
    bool ret = CloseHandle(ti->handle);
    assert(ret);
    ret = dynarr_remove(&gitstatus_threads, idx);
    assert(ret);
}


static bool remove_running_thread(const char *workdir)
{
    for (unsigned i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        assert(ti);
        // PERF: we compare by path for logging.
        // We should compare by handle for performance
        if (strcmp(workdir, ti->workdir)) continue;

        remove_running_thread_idx(i);
        return true;
    }

    return false;
}


static bool get_running_thread(const char *workdir, HANDLE *t)
{
    assert(workdir != NULL);

    for (unsigned i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        assert(ti);
        if (strcmp(workdir, ti->workdir)) continue;

        DWORD code;
        bool ret = GetExitCodeThread(ti->handle, &code);
        assert(ret);

        if (code == STILL_ACTIVE) {
            *t = ti->handle;
            return true;
        }

        remove_running_thread_idx(i);
        return false;
    }

    return false;
}


static bool append_running_thread(const char *workdir, HANDLE t)
{
    ThreadItem ti;
    ti.handle = t;
    errno_t err = strncpy_s(ti.workdir, MAX_PATH, workdir, _TRUNCATE);
    assert(!err || err == STRUNCATE);

    bool ret = dynarr_append(&gitstatus_threads, &ti);
    assert(ret);
    return true;
}


/// Gitstatus cache management

// '?99999 +99999 m99999 x99999'
#define STATUS_SIZE 28
#define BRANCH_SIZE 20

typedef struct {
    char workdir[MAX_PATH];
    char branch[BRANCH_SIZE];
    char status[STATUS_SIZE];
} StatusItem;

// PERF: linear search for long paths?
static DynArr status_cache;
static HANDLE g_status_cache_mutex = NULL;

static StatusItem *status_cache_get(const char *workdir)
{
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    StatusItem *si = NULL;
    for (unsigned i = 0; i < status_cache.count; ++i) {
        StatusItem *test = dynarr_at(&status_cache, i);
        if (strcmp(test->workdir, workdir)) continue;
        si = test;
        break;
    }

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return si;
}


static bool status_cache_append(StatusItem *si)
{
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    StatusItem *_si = dynarr_append(&status_cache, si);
    assert(_si != NULL);

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return true;
}


static bool status_cache_remove(const char *workdir)
{
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    bool removed = false;
    for (unsigned i = 0; i < status_cache.count; ++i) {
        StatusItem *test = dynarr_at(&status_cache, i);
        if (strcmp(test->workdir, workdir)) continue;
        removed = dynarr_remove(&status_cache, i);
        assert(removed);
        break;
    }

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return removed;
}


/// Filesystem monitor. Invalidates gitstatus cache on fs events.

static HANDLE g_fsmon_thread = NULL;
static HANDLE g_fsmon_event = NULL;
static char g_fsmon_workdir[MAX_PATH];
static wchar_t g_fsmon_remote[MAX_PATH];

static bool fsmon_invalidate_idx(DynArr *events, DynArr *os, DynArr *remotes, unsigned idx)
{
    assert(idx >= 1 && "First event is g_fsmon_event, not dir");

    HANDLE *dir = dynarr_at(events, idx); assert(dir != NULL);
    char path[MAX_PATH];
    if (!GetFinalPathNameByHandleA(*dir, path, MAX_PATH, FILE_NAME_OPENED))
        return false;

    errno_t et = strcat_s(path, MAX_PATH, "/");
    assert(!et);

    char *workdir = path + 4;  // "\\?\"
    char *ptr = workdir;
    while (*ptr++) if (*ptr == '\\') *ptr = '/';

    bool ret = status_cache_remove(workdir);
    assert(ret);

    ret = CloseHandle(*dir);
    assert(ret);
    ret = dynarr_remove(events, idx);
    assert(ret);
    ret = dynarr_remove(os, idx);
    assert(ret);
    ret = dynarr_remove(remotes, idx);
    assert(ret);

    return true;
}


static bool changes_invalidate(char *buf, WCHAR *remote_path)
{
    while (1) {
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buf;

        WCHAR *filename = fni->FileName;  // not null terminated
        DWORD len = fni->FileNameLength;  // in bytes
        filename[len / 2] = 0;

        bool startswith_dotgit = memcmp(filename, L".git", 8)         == 0;
        bool is_head           = memcmp(filename, L".git\\HEAD", 20)  == 0;
        bool is_index          = memcmp(filename, L".git\\index", 22) == 0;
        bool is_remote         = wcscmp(filename, remote_path)        == 0;

        if (!startswith_dotgit || is_head || is_index || is_remote) return true;

        if (!fni->NextEntryOffset) break;
        buf += fni->NextEntryOffset;
    }

    return false;
}


#define CHANGES_SIZE 1024

static unsigned long fsmon_daemon_thread_proc(void *param)
{
    DynArr events  = dynarr_init_ex(sizeof(HANDLE), 4);
    DynArr os      = dynarr_init_ex(sizeof(OVERLAPPED), 4);
    DynArr remotes = dynarr_init_ex(sizeof(WCHAR) * MAX_PATH, 4);
    dynarr_append(&events, &g_fsmon_event);
    dynarr_append_zeroed(&os);
    dynarr_append_zeroed(&remotes);

    DWORD filter =
        FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        // | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION
        ;

    bool ret;
    char changes[CHANGES_SIZE];
    while (1) {
        unsigned long idx = WaitForMultipleObjects(
            (DWORD)events.count, events._data, false, INFINITE);
        if (idx >= events.count) return 1;

        if (idx == 0) {
            if (*g_fsmon_workdir == 0) {
                for (unsigned i = 0; i < events.count; ++i) {
                    HANDLE *h = dynarr_at(&events, i);
                    ret = CloseHandle(*h);
                    assert(ret);
                }
                dynarr_free(&events);
                dynarr_free(&os);
                break;
            }

            if (events.count == MAXIMUM_WAIT_OBJECTS) {
                ret = fsmon_invalidate_idx(&events, &os, &remotes, 1);
                assert(ret);
            }

            HANDLE dir = CreateFileA(
                    g_fsmon_workdir,
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    NULL);
            assert(dir != INVALID_HANDLE_VALUE);

            OVERLAPPED *o = dynarr_append_zeroed(&os);
            assert(o != NULL);
            bool ret = ReadDirectoryChangesW(
                dir, changes, CHANGES_SIZE, true, filter, NULL, o, NULL);
            assert(ret);

            dynarr_append(&events, &dir);
            dynarr_append(&remotes, g_fsmon_remote);
            continue;
        }

        OVERLAPPED *o = dynarr_at(&os, idx);
        assert(o != NULL);
        HANDLE *dir = dynarr_at(&events, idx);
        assert(dir != NULL);

        unsigned long returned = 0;
        ret = GetOverlappedResult(*dir, o, &returned, false);
        assert(ret);  // if we waited on handle, `changes` must be ready

        WCHAR *remote_path = dynarr_at(&remotes, idx);
        assert(remote_path);
        if (returned && changes_invalidate(changes, remote_path)) {
            ret = fsmon_invalidate_idx(&events, &os, &remotes, idx);
            assert(ret);
            continue;
        }

        ret = ReadDirectoryChangesW(
            *dir, changes, CHANGES_SIZE, true, filter, NULL, o, NULL);
        assert(ret);
    }

    return 0;
}


/// Thread proc for gitstatus

typedef struct {
    unsigned i_new;
    unsigned i_modified;
    unsigned i_deleted;
    unsigned i_renamed;
    unsigned i_typechange;
    unsigned wt_new;
    unsigned wt_modified;
    unsigned wt_deleted;
    unsigned wt_typechange;
    unsigned wt_renamed;
    unsigned wt_unreadable;
    // unsigned ignored;
    unsigned conflicted;
} RetStatus;

#define WORK_BUF MAX_PATH

static unsigned long gitstatus_thread_proc(void *_root)
{
    git_buf *root = _root;
    StatusItem si = {0};
    int w;

    git_repository *repo = NULL;
    int error = git_repository_open(&repo, root->ptr);
    assert(!error);

    git_reference *head = NULL;
    error = git_reference_lookup(&head, repo, "HEAD");
    assert(!error);

    const char *branch = NULL;

    if (git_repository_head_detached(repo)) {
        const git_oid *det = git_reference_target(head);
        char buf[GIT_OID_SHA1_HEXSIZE + 1] = {0};
        char *ret = git_oid_tostr(buf, GIT_OID_SHA1_HEXSIZE + 1, det);
        w = snprintf(si.branch, sizeof(si.branch), "detached at %s", buf);
        assert(w > 0);
    } else {
        assert(git_reference_type(head) == GIT_REFERENCE_SYMBOLIC);
        const char *target = git_reference_symbolic_target(head);
        assert(target);
        branch = strrchr(target, '/');
        branch++;

        w = snprintf(si.branch, sizeof(si.branch), "%s", branch);
        assert(w > 0);
        if (w > sizeof(si.branch))
            for (int i = 1; i < 4; i++)
                si.branch[BRANCH_SIZE - i] = '.';
    }

    // TODO: Check if updating the index is a good idea
    git_status_options opts = {
        .version = GIT_STATUS_OPTIONS_VERSION,
        .flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED
               | GIT_STATUS_OPT_EXCLUDE_SUBMODULES
               | GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX
               | GIT_STATUS_OPT_RENAMES_INDEX_TO_WORKDIR
               // | GIT_STATUS_OPT_UPDATE_INDEX
               | GIT_STATUS_OPT_INCLUDE_UNREADABLE
    };

    git_status_list *statuses = NULL;
    error = git_status_list_new(&statuses, repo, &opts);
    if (error) return 3;

    RetStatus rs = {0};
    size_t count = git_status_list_entrycount(statuses);
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry *entry = git_status_byindex(statuses, i);

        rs.i_new         += !!(entry->status & GIT_STATUS_INDEX_NEW);
        rs.i_modified    += !!(entry->status & GIT_STATUS_INDEX_MODIFIED);
        rs.i_deleted     += !!(entry->status & GIT_STATUS_INDEX_DELETED);
        rs.i_renamed     += !!(entry->status & GIT_STATUS_INDEX_RENAMED);
        rs.i_typechange  += !!(entry->status & GIT_STATUS_INDEX_TYPECHANGE);
        rs.wt_new        += !!(entry->status & GIT_STATUS_WT_NEW);
        rs.wt_modified   += !!(entry->status & GIT_STATUS_WT_MODIFIED);
        rs.wt_deleted    += !!(entry->status & GIT_STATUS_WT_DELETED);
        rs.wt_typechange += !!(entry->status & GIT_STATUS_WT_TYPECHANGE);
        rs.wt_renamed    += !!(entry->status & GIT_STATUS_WT_RENAMED);
        rs.wt_unreadable += !!(entry->status & GIT_STATUS_WT_UNREADABLE);
        // rs.ignored       += !!(entry->status & GIT_STATUS_IGNORED);
        rs.conflicted    += !!(entry->status & GIT_STATUS_CONFLICTED);
    }

    char *signs[] = { "?", "+", "m", "x", "mv", "t", "u", /*"i",*/ "c" };
    int values[] = {
        rs.wt_new,
        rs.i_new,
        rs.i_modified + rs.wt_modified,
        rs.i_deleted + rs.wt_deleted,
        rs.i_renamed + rs.wt_renamed,
        rs.i_typechange + rs.wt_typechange,
        rs.wt_unreadable,
        // rs.ignored,
        rs.conflicted
    };
    static_assert(_countof(signs) == _countof(values), "");

    char *p = si.status;
    for (int i = 0; i < _countof(values); ++i) {
        if (!values[i]) continue;

        if (*si.status) { *p = ' '; p++; }
        size_t available = STATUS_SIZE - ((size_t)p - (size_t)si.status);
        w = snprintf(p, available, "%s%i", signs[i], values[i]);
        if (w < 0) return 4;

        if (w > available) {
            for (int i = 1; i < 4; i++)
                si.status[STATUS_SIZE - i] = '.';
            break;
        }
        p += w;
    }

    w = snprintf(g_fsmon_workdir, MAX_PATH, "%s", root->ptr);
    assert(w > 0 && w < MAX_PATH);

    *g_fsmon_remote = 0;

    git_remote *rm = NULL;
    git_strarray arr = {0};

    // TODO: Only report sync if there is nothing else? It is a useful thing to
    // know all the times. Check how expensive it is.
    if (p == si.status && branch && !git_remote_list(&arr, repo) && arr.count) {
        git_oid head;
        error = git_reference_name_to_id(&head, repo, "HEAD");
        if (error) goto out_label;
        char hash_head[GIT_OID_SHA1_HEXSIZE + 1] = {0};
        char *ret = git_oid_tostr(hash_head, GIT_OID_SHA1_HEXSIZE + 1, &head);
        if (ret == NULL) goto out_label;

        // TODO: Is it safe to presume `arr.strings[0]` is ALWAYS what we want?
        char refname[MAX_PATH];
        w = sprintf(refname, "refs/remotes/%s/%s", arr.strings[0], branch);
        assert(w > 0);

        git_oid remote;
        error = git_reference_name_to_id(&remote, repo, refname);
        if (error) goto out_label;
        char hash_remote[GIT_OID_SHA1_HEXSIZE + 1] = {0};
        ret = git_oid_tostr(hash_remote, GIT_OID_SHA1_HEXSIZE + 1, &remote);
        if (ret == NULL) goto out_label;

        if (strcmp(hash_head, hash_remote) == 0) goto out_label;
        strcat(si.status, "󰶣");

        // Construct path for fsmon to listen
        wchar_t refname_wide[MAX_PATH];
        w = MultiByteToWideChar(CP_UTF8, 0, refname, -1, refname_wide, MAX_PATH);
        assert(w > 0);
        wchar_t remote_path[MAX_PATH];
        w = swprintf(remote_path, sizeof(remote_path), L".git/%s", refname_wide);
        assert(w > 0);

        wchar_t *cpy = wcscpy(g_fsmon_remote, remote_path);
        assert(cpy);
        wchar_t *p = cpy;
        while (*p) { if (*p == '/') *p = '\\'; p++; }
    }
out_label:

    w = snprintf(si.workdir, MAX_PATH, "%s", root->ptr);
    assert(w > 0 && w < MAX_PATH);

    static bool fsmon_created = false;
    if (!fsmon_created) {
        fsmon_created = true;
        g_fsmon_thread = CreateThread(NULL, 0, fsmon_daemon_thread_proc, NULL, 0, NULL);
        if (g_fsmon_thread == NULL) return 5;
    }
    if (!SetEvent(g_fsmon_event)) {
        printf("git thread could not set event for fsmon thread\n");
        return 6;
    }

    bool ret = status_cache_append(&si);
    assert(ret);

    git_reference_free(head);
    git_strarray_dispose(&arr);
    git_remote_free(rm);
    git_repository_free(repo);
    git_status_list_free(statuses);
    git_buf_dispose(root);
    free(root);

    return 0;
}


/// Server functions

#define MAX_REFPATH 30

typedef struct {
    char path[MAX_PATH];
    char refpath[MAX_REFPATH];
} PathItem;

static DynArr refpath_cache;

static bool set_valid_path(char *dest, const char *path)
{
    if (strlen(path) >= MAX_PATH ||
        PathGetDriveNumberA(path) < 0 ||
        !PathCanonicalizeA(dest, path)
    ) return false;

    PathRemoveBackslashA(dest);

    return true;
}


static bool add_refpath(const char *final_path, const char *refpath)
{
    bool refpath_given = refpath != NULL;

    // If path is just C, C:, or C:\ don't add
    if (!refpath_given) {
        char *last = strrchr(final_path, '\\');
        if (last == NULL) return false;
        refpath = last + 1;
        if (!*refpath) return false;
    }

    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);
        assert(pi->path);

        if (refpath_given) {
            if (strcmp(pi->refpath, refpath) == 0) return false;

        } else {
            if (strcmp(pi->path, final_path) == 0) return false;
        }
    }

    PathItem pi;
    errno_t err = strncpy_s(pi.path, MAX_PATH, final_path, _TRUNCATE);
    assert(!err);

    err = strncpy_s(pi.refpath, MAX_REFPATH, refpath, _TRUNCATE);
    assert(!err || err == STRUNCATE);

    dynarr_append(&refpath_cache, &pi);

    return true;
}


static bool handle_refadd(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *path = g_ctx->transfer.data;
    if (!path) return false;

    size_t pathlen = strlen(path);
    char *refpath = path + pathlen + 1;
    if (!*refpath) refpath = NULL;

    char final_path[MAX_PATH];
    if (!set_valid_path(final_path, path) || !PathFileExistsA(final_path))
        return false;

    return add_refpath(final_path, refpath);
}


static bool handle_refget(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *refpath = g_ctx->transfer.data;
    if (!refpath) return false;

    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);
        if (_stricmp(pi->refpath, refpath) == 0) {
            int written = sprintf(g_ctx->transfer.data, "%s", pi->path);
            g_ctx->transfer.headers.data_size = written + 1;
            return true;
        }
    }

    return false;
}


static bool handle_refdel(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *what = g_ctx->transfer.data;
    bool is_refpath = *what++;

    char *target = what;
    char final_path[MAX_PATH];
    if (!is_refpath) {
        if (!set_valid_path(final_path, what) || !PathFileExistsA(final_path)) return false;
        target = final_path;
    }

    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);

        char *it = pi->path;
        if (is_refpath) it = pi->refpath;

        if (strcmp(it, target) == 0) {
            bool ret = dynarr_remove(&refpath_cache, i);
            assert(ret);
            return true;
        }
    }

    return false;
}


static bool handle_move_down(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *refpath = g_ctx->transfer.data;

    for (unsigned i = 0; i < refpath_cache.count; ++i) {

        PathItem *pi = dynarr_at(&refpath_cache, i);
        if (_stricmp(pi->refpath, refpath)) continue;

        PathItem save = *pi;
        bool ret = dynarr_remove(&refpath_cache, i);
        assert(ret);
        dynarr_append(&refpath_cache, &save);

        return true;
    }

    return false;
}


static bool handle_refgetall(void)
{
    static_assert(sizeof(int) == 4 && INT32_MAX > DATA_CAPACITY, "");
    g_ctx->transfer.headers.data_size = 0;
    int written = 0;
    char *dest = g_ctx->transfer.data;
    *dest = 0;

    // It would take around 6k entries for this thing to not fit
    // into one transfer. After years of using this I'm at 91...
    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);

        char *mask = "%s;";
        if (i == refpath_cache.count - 1) mask = "%s";

        int it_written = snprintf(dest + written, DATA_CAPACITY - written, mask, pi->refpath);
        if (it_written < 0 || (unsigned)it_written > DATA_CAPACITY - written) return false;

        written += it_written;
    }

    written++;
    g_ctx->transfer.headers.data_size = written;
    return true;
}


static FILE *get_cache_file(const char *mode)
{
    const char *const localappdata = getenv("localappdata");
    if (localappdata == NULL) return NULL;

    const char *filename = "ShellServer\\nss.dat";
    char filepath[MAX_PATH];
    int w = snprintf(filepath, MAX_PATH, "%s\\%s", localappdata, filename);
    if (w < 0 || w >= MAX_PATH) return NULL;

    FILE *file;
    errno_t err = fopen_s(&file, filepath, mode);
    if (err) return NULL;

    return file;
}


static bool handle_save_cache(void)
{
    g_ctx->transfer.headers.data_size = 0;

    FILE *file = get_cache_file("wb");
    if (file == NULL) return false;

    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);
        assert(pi);

        int w = fprintf(file, "%s;%s;", pi->refpath, pi->path);
        if (w < 0) {
            fclose(file);
            return false;
        }
    }

    fclose(file);
    return true;
}


static bool load_fs_stored_cache(DynArr *da)
{
    char *content = g_ctx->transfer.data;
    *content = 0;

    FILE *file = get_cache_file("rb");
    if (!file) return false;

    while (!feof(file)) {
        int r = fread(content, 1, DATA_CAPACITY, file);
        if (ferror(file)) return false;
        content[r] = 0;

        // TODO: test this case
        if (!feof(file)) {
            int count = 0;
            for (int i = 0; i < DATA_CAPACITY; ++i)
                if (content[i] == ';')
                    count++;

            // ;refpath;path;ref_unterm\0
            //              ^
            char *last = strrchr(content, ';'); assert(last);

            if (count % 2 != 0) {
                // ;refpath\0path_unterm
                // ^
                *last = 0;
                last = strrchr(content, ';'); assert(last);
            }

            last++;
            *last = 0;
            int err = fseek(file, (int64_t)last - (int64_t)content, SEEK_SET);
            assert(!err);
        }

        PathItem pi;
        char *tok, *ntok;

        tok = strtok_s(content, ";", &ntok); assert(tok);

        do {
            int w = snprintf(pi.refpath, MAX_REFPATH, "%s", tok);
            if (w < 0 || w >= MAX_REFPATH) abort();

            tok = strtok_s(NULL, ";", &ntok); assert(tok);
            w = snprintf(pi.path, MAX_PATH, "%s", tok);
            if (w < 0 || w >= MAX_PATH) abort();

            bool ret = dynarr_set_append(da, &pi);
            assert(ret);

        } while ((tok = strtok_s(NULL, ";", &ntok)));
    }

    fclose(file);
    return true;
}


#define DUMP_MASK "%s: %s\n"

static bool handle_dump_mem(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *dest = g_ctx->transfer.data;
    *dest = 0;

    // TODO: handle if all data doesn't fit DATA_CAPACITY
    int written = 0;
    for (unsigned i = 0; i < refpath_cache.count; ++i) {
        PathItem *pi = dynarr_at(&refpath_cache, i);
        assert(pi);

        size_t available = DATA_CAPACITY - written;
        int w = snprintf(dest, available, DUMP_MASK, pi->refpath, pi->path);
        if (w < 0 || w >= available) return false;

        written += w;
        dest += w;
    }

    int null = 1;
    g_ctx->transfer.headers.data_size = written + null;
    return true;
}


static bool handle_dump_stored(void)
{
    g_ctx->transfer.headers.data_size = 0;
    char *dest = g_ctx->transfer.data;
    *dest = 0;

    DynArr da = dynarr_init(sizeof(PathItem));
    if (!load_fs_stored_cache(&da)) return false;

    // TODO: handle if all data doesn't fit DATA_CAPACITY
    int written = 0;
    for (unsigned i = 0; i < da.count; ++i) {
        PathItem *pi = dynarr_at(&da, i); assert(pi);

        size_t available = DATA_CAPACITY - written;
        int w = snprintf(dest, available, DUMP_MASK, pi->refpath, pi->path);
        if (w < 0 || w >= available) return false;
        written += w;
        dest += w;
    }

    dynarr_free(&da);

    int null = 1;
    g_ctx->transfer.headers.data_size = written + null;
    return true;
}


/// Prompt

typedef struct {
    char *text;
    unsigned len;
} Comp;

static void format_duration(char buf[7], unsigned duration)
{
    int written;
    unsigned h, m, s;
    s = duration / 1000;
    m = s / 60;
    h = m / 60;

    if (h >= 100) return;
    if (h) {
        written = sprintf(buf, "%uh%um", h, m%60);
        assert(written > 0 && written < 7);
        return;
    }

    if (m) {
        written = sprintf(buf, "%um%us", m, s%60);
        assert(written > 0 && written < 7);
        return;
    }

    written = sprintf(buf, "%.1fs", (float)duration/1000);
    assert(written > 0 && written < 7);
}


static void set_extensions(const char *path, long *mask, bool *access_denied)
{
    static_assert(sizeof(*mask) * 8 >= EXT_TOTAL, "");

    char path_glob[MAX_PATH];
    int written = sprintf_s(path_glob, MAX_PATH, "%s\\*", path);
    if (written <= 0 || written >= MAX_PATH) return;

    // PERF: FindFirstFileExW is the hottest spot
    WIN32_FIND_DATAA fd;
    HANDLE find = FindFirstFileExA(
            path_glob,
            FindExInfoBasic,
            &fd,
            FindExSearchNameMatch,
            NULL,
            FIND_FIRST_EX_LARGE_FETCH
    );
    if (find == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED) *access_denied = true;
        return;
    }

    while (FindNextFileA(find, &fd)) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)) continue;

        char *ext = strrchr(fd.cFileName, '.');
        if (!ext) continue;
        ext++;

        for (int i = 0; i < EXT_TOTAL; ++i) {
            if (_bittest(mask, i)) continue;

            for (wchar_t j = 0; j < extensions[i].count; ++j) {
                if (strcmp(ext, extensions[i].ext_name[j]) == 0) {
                    _bittestandset(mask, i);
                    break;
                }
            }
        }
    }

    bool success = FindClose(find);
    assert(success);
}


// This function ASSUMES valid utf8. The right return value should be size_t
// but this thing will run on DATA_CAPACITY max, which fits on u16
static unsigned short utf8len(const char *str)
{
    unsigned short count = 0;
    long c;

    while ((c = (long)*str)) {
        unsigned char msb = _bittest(&c, 7);
        unsigned long idx;
        _BitScanForward(&idx, c >> 4);

        unsigned char add = (unsigned char)(1 + msb * (3 - idx));
        count++;
        str += add;
    }

    return count;
}


static void set_status_item(StatusItem *si, bool *has_git, const char *final_path)
{
    git_buf *root = malloc(sizeof(git_buf));
    int err = git_repository_discover(root, final_path, 0, NULL);
    if (err) return;

    // some/path/.git/
    char *x = strrchr(root->ptr, '.');
    assert(x && x > root->ptr && x < root->ptr + root->size);
    *x = 0;
    // some/path/

    // I use this variable bc si.workdir is set only in gsthread for cache
    // control, maybe it can be removed if we do a two-phase cache add, but it
    // feels like too much
    *has_git = true;

    StatusItem *_si = status_cache_get(root->ptr);
    if (_si != NULL) {
        *si = *_si;
        git_buf_dispose(root);
        free(root);
        return;
    }

    char workdir[MAX_PATH];
    errno_t et = strcpy_s(workdir, MAX_PATH, root->ptr);
    assert(!et);

    HANDLE thread = NULL;
    bool root_given_to_thread = false;
    if (!get_running_thread(workdir, &thread)) {
        thread = CreateThread(NULL, 0, gitstatus_thread_proc, root, 0, NULL);
        bool ret = append_running_thread(workdir, thread);
        assert(ret);
        root_given_to_thread = true;
    }
    assert(thread != NULL);

    DWORD wait = WaitForSingleObject(thread, GITSTATUS_TIMEOUT);
    switch (wait) {
        case WAIT_OBJECT_0:

            DWORD code;
            bool ret = GetExitCodeThread(thread, &code);
            assert(ret);

            ret = remove_running_thread(workdir);
            assert(ret);

            if (code != 0) {
                printf(
                    "-------\n"
                    "Thread exit code for %s is %lu\n"
                    "-------\n",
                    workdir, code);
                assert(0 && "Thread error");
                abort();
            }

            _si = status_cache_get(workdir);
            assert(_si != NULL);
            *si = *_si;

            break;

        case WAIT_TIMEOUT:
            break;

        case WAIT_FAILED:
        case WAIT_ABANDONED:
        default:
            assert(0 && "unreachable");
            abort();
    }

    if (root_given_to_thread) return;

    git_buf_dispose(root);
    free(root);
}


static Comp transfer_data_snprintf(char **where, int *available, char *mask, ...)
{
    Comp ret = { .text = *where };

    va_list ap;
    va_start(ap, mask);
    int w = vsnprintf(*where, *available, mask, ap);
    // TODO: abort?
    if (w <= 0 || w >= *available) abort();
    va_end(ap);

    ret.len = utf8len(*where);

    *where += w + 1;
    *available -= w + 1;

    return ret;
}


// TODO: remove these macros and do through functions, like
// `transfer_data_snprintf`
#define push_color(color) do {            \
    written = term_buf_sgr(dest, color);  \
    dest += written;                      \
    dest_available -= written;            \
} while(0)

#define push_text(...) do {                                 \
    written = snprintf(dest, dest_available, __VA_ARGS__);  \
    dest += written;                                        \
    dest_available -= written;                              \
} while (0)


static bool handle_prompt(void)
{
    unsigned short data_size = g_ctx->transfer.headers.data_size;
    g_ctx->transfer.headers.data_size = 0;
    if (data_size > sizeof(PromptData) + MAX_PATH - 3) return false;  // -3: \\*\0

    PromptData *pd = (PromptData *)g_ctx->transfer.data;
    int screen_width    = pd->screen_width;
    short error_code    = pd->error_code;
    unsigned cmd_dur_ms = pd->cmd_dur_ms;

    char final_path[MAX_PATH];
    if (!set_valid_path(final_path, pd->path)) return false;

    long extmask = 0;
    bool access_denied = false;
    bool file_exists = PathFileExistsA(final_path);

    // We need to check access_denied again inside `set_extensions` because we
    // may have permission to see the path, but not to list it. And we will
    // treat both cases the same way
    if (file_exists) set_extensions(final_path, &extmask, &access_denied);
    else access_denied = GetLastError() == ERROR_ACCESS_DENIED;

    const char *const userprofile = getenv("USERPROFILE");
    if (userprofile == NULL) return false;
    if (file_exists && _stricmp(userprofile, final_path))
        add_refpath(final_path, NULL);

    StatusItem si = {0};
    bool has_git = false;
    set_status_item(&si, &has_git, final_path);

    // Feels dumb to alloc more when we have lots of unused space in
    // g_ctx.transfer.data (DATA_CAPACITY: 65507 - headers)
    int tmp_available, dest_available, written;
    tmp_available = dest_available = DATA_CAPACITY / 2;
    char *tmp = g_ctx->transfer.data + dest_available;
    char *dest = g_ctx->transfer.data;

    /// Populate components
    char buf[WORK_BUF] = {0};
    Comp duration = {""};
    if (cmd_dur_ms > CMD_DUR_THRESHOLD) {
        format_duration(buf, cmd_dur_ms);
        duration = transfer_data_snprintf(&tmp, &tmp_available, " %s", buf);
    }

    time_t t;
    struct tm timeinfo;
    time(&t);
    errno_t err = localtime_s(&timeinfo, &t);
    assert(!err);

    int h, m, s;
    h = timeinfo.tm_hour;
    m = timeinfo.tm_min;
    s = timeinfo.tm_sec;

    // TODO: the clock in my font is rendered on two columns, so '+ 1' on len.
    // Check if it happens with other fonts
    Comp clock = transfer_data_snprintf(&tmp, &tmp_available, "🕓 %02i:%02i:%02i", h, m, s);
    clock.len++;

    Comp icon = { "", 1 };
    if (strcmp(userprofile, final_path) == 0) {
        icon.text = "";
    } else if (access_denied) {
        icon.text = "";
    }

    Comp render_path = {final_path};
    char *test = strstr(final_path, userprofile);
    if (test == final_path) {
        render_path.text = final_path + strlen(userprofile) - 1;
        *render_path.text = '~';
    }
    render_path.len = utf8len(render_path.text);

    Comp git = {""};
    Comp branch = {""};
    Comp status = {""};

    if (has_git) {
        git.text = "";
        git.len = 1;

        if (*si.branch) {
            branch = transfer_data_snprintf(&tmp, &tmp_available, " %s", si.branch);
        } else {
            branch.text = "...";
            branch.len = 3;
        }
    }

    if (*si.status) {
        status.text = si.status;
        status.len = utf8len(si.status);
    }

    int ext_count = 0;
    for (int i = 0; i < EXT_TOTAL; ++i) {
        if (_bittest(&extmask, i)) ext_count++;
    }

    /// Count and operate on components sizes
    int right_size = clock.len;
    if (duration.len) right_size += duration.len + 1;

    int space = 1;
    int bracket = 1;
    int left_size = icon.len + space + render_path.len;
    if (git.len)    left_size += space + git.len;
    if (branch.len) left_size += space + bracket + branch.len + bracket;
    if (status.len) left_size += space + bracket + status.len + bracket;
    if (ext_count)  left_size += space + ext_count * 2 - 1;

    int empty = screen_width - left_size - right_size;
    if (empty < 1) {
        clock.text = "";
        clock.len = 0;
        right_size = duration.len;
        empty = screen_width - left_size - right_size;
    }

    if ((right_size && empty < 1) || (!right_size && empty < 0)) {
        empty = right_size ? 1 : 0;
        int over = left_size + empty + right_size - screen_width;
        assert(over > 0);

        unsigned out_size = render_path.len - over + 1;
        BOOL b = PathCompactPathExA(buf, render_path.text, out_size, 0);
        assert(b);

        render_path.text = buf;
        left_size -= over;
    }

    assert(left_size + empty + right_size == screen_width);

    /// Now render everything
    if (access_denied) push_color(SGR_BF_RED);
    else push_color(SGR_BF_CYAN);
    push_text("%s ", icon.text);

    push_color(SGR_BF_CYAN);
    push_text("%s", render_path.text);

    if (git.len) {
        push_color(SGR_BF_RED);
        push_text(" %s ", git.text);

        push_color(SGR_DEFAULT);
        push_text("[");
            push_color(SGR_BF_MAGENTA);
            push_text("%s", branch.text);
        push_color(SGR_DEFAULT);
        push_text("]");
    }

    if (status.len) {
        push_text(" [");
        push_color(SGR_BF_RED);
        push_text("%s", status.text);
        push_color(SGR_DEFAULT);
        push_text("]");
    }

    for (int i = 0; i < EXT_TOTAL; ++i) {
        if (_bittest(&extmask, i)) {
            push_color(extmapcolor[i]);
            push_text(" %s", extmapsign[i]);
        }
    }

    push_color(SGR_DEFAULT);
    push_text("%*s", empty, "");

    if (duration.len)              push_text("%s", duration.text);
    if (duration.len && clock.len) push_text(" ");
    if (clock.len)                 push_text("%s", clock.text);

    // ❯
    push_color(error_code ? SGR_BF_RED : SGR_BF_GREEN);
    push_text("%s", "❯ ");
    push_color(SGR_DEFAULT);

    assert(dest_available >= 0);
    g_ctx->transfer.headers.data_size = DATA_CAPACITY / 2 - (unsigned short)dest_available + 1;

    // More than 30k on each...
    // printf("available: dest: %i; tmp: %i\n", dest_available, tmp_available);

    return true;
}

#undef push_color
#undef push_text


/// Entry point

#ifdef NDEBUG
int WinMain(HINSTANCE instance, HINSTANCE prev, LPSTR cmdline, int showcmd)
{
#else
int main(int argc, char **argv)
{
    if (argc > 1) g_port = atoi(argv[1]);
    assert(printf("Assert is on\n"));
#endif
    // Setup
    if (!ss_init()) return 1;

    int res = bind(
            g_ctx->sock,
            (struct sockaddr *)&g_ctx->addr,
            sizeof(g_ctx->addr)
    );
    if (res == SOCKET_ERROR) {
        printf("Could not bind server\n");
        return 1;
    }

    git_libgit2_init();
    refpath_cache     = dynarr_init(sizeof(PathItem));
    status_cache      = dynarr_init(sizeof(StatusItem));
    gitstatus_threads = dynarr_init(sizeof(ThreadItem));

#ifdef NDEBUG
    load_fs_stored_cache(&refpath_cache);
#endif

    g_status_cache_mutex = CreateMutexW(NULL, false, NULL);
    if (g_status_cache_mutex == NULL) return 1;
    g_fsmon_event  = CreateEventW(NULL, false, false, NULL);
    if (g_fsmon_event == INVALID_HANDLE_VALUE) return 1;

    // Mainloop
    while (true) {
        if (!_ss_recv()) return 1;

        if (memcmp(g_ctx->transfer.headers.magic, g_transfer_magic, 4) != 0) {
            printf("Magic mismatch: DoSing\n");
            continue;
        }

        bool quit = false;
        bool dos  = false;
        switch (g_ctx->transfer.headers.kind) {
            case MK_ECHO:
                g_ctx->transfer.headers.success = true;
                printf("MK_ECHO\n");
                break;

            case MK_PROMPT:
                bool success = handle_prompt();
                g_ctx->transfer.headers.success = success;
                printf("MK_PROMPT: %s\n", success ? "true" : "false");
                break;

            case MK_REFADD:
                success = handle_refadd();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFADD: %s\n", success ? "true" : "false");
                break;

            case MK_REFGET:
                success = handle_refget();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFGET: %s\n", success ? "true" : "false");
                break;

            case MK_REFDEL:
                success = handle_refdel();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFDEL: %s\n", success ? "true" : "false");
                break;

            case MK_MVREFDOWN:
                success = handle_move_down();
                g_ctx->transfer.headers.success = success;
                printf("MK_MVREFDOWN: %s\n", success ? "true" : "false");
                break;

            case MK_REFGETALL:
                success = handle_refgetall();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFGETALL: %s\n", success ? "true" : "false");
                break;

            case MK_DUMP_MEM:
                success = handle_dump_mem();
                g_ctx->transfer.headers.success = success;
                printf("MK_DUMP_MEM: %s\n", success ? "true" : "false");
                break;

            case MK_DUMP_DISK:
                success = handle_dump_stored();
                g_ctx->transfer.headers.success = success;
                printf("MK_DUMP_DISK: %s\n", success ? "true" : "false");
                break;

            case MK_SAVE:
                success = handle_save_cache();
                g_ctx->transfer.headers.success = success;
                printf("MK_SAVE: %s\n", success ? "true" : "false");
                break;

            case MK_QUIT:
                quit = true;
                g_ctx->transfer.headers.success = true;
                g_ctx->transfer.headers.data_size = 0;
                printf("MK_QUIT\n");
                break;

            default:
                printf("Received unknow message\n");
                dos = true;
                break;
        }

        if (dos) continue;

        if (!_ss_send()) return 1;

        if (quit) break;
    }

    // Cleanup
    bool ret;
    DWORD wait;
    for (unsigned i = 0; i < gitstatus_threads.count; ++i) {
        // libgit might be writing to disk, don't kill thread
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        wait = WaitForSingleObject(ti->handle, INFINITE);
        assert(wait == WAIT_OBJECT_0);
        DWORD code;
        ret = GetExitCodeThread(ti->handle, &code);
        assert(ret);
        assert(code == 0);
        ret = CloseHandle(ti->handle);
        assert(ret);
    }
    ret = CloseHandle(g_status_cache_mutex);
    assert(ret);

    if (g_fsmon_thread) {
        // This is how we tell fsmon thread to shutdown
        *g_fsmon_workdir = 0;
        ret = SetEvent(g_fsmon_event);
        assert(ret);

        wait = WaitForSingleObject(g_fsmon_thread, INFINITE);
        assert(wait == WAIT_OBJECT_0);
        ret = CloseHandle(g_fsmon_thread);
        assert(ret);
    }

    dynarr_free(&refpath_cache);
    dynarr_free(&status_cache);
    dynarr_free(&gitstatus_threads);
    git_libgit2_shutdown();
    ss_shutdown();

    return 0;
}

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


#define GITSTATUS_TIMEOUT 300
#define CMD_DUR_THRESHOLD 200
#define CHANGES_SIZE 1024

enum {
    HAS_C,
    HAS_CPP,
    EXT_TOTAL
};

#define MAX_EXT_STR_SIZE 4
// TODO: this size as first element is dumb
static char *extensions[EXT_TOTAL][MAX_EXT_STR_SIZE] = {
    [HAS_C]   = {"\x02" , "c", "h"},
    [HAS_CPP] = {"\x03" , "cpp", "hh", "hpp"}
};

static char *extmapsign[EXT_TOTAL] = {
    [HAS_C]   = "",
    [HAS_CPP] = "",
};

static SetGraphicsRendition extmapcolor[EXT_TOTAL] = {
    [HAS_C]   = SGR_F_BLUE,
    [HAS_CPP] = SGR_F_BLUE
};


// Return true if we don't have permission to list dir
static bool set_extensions(const char *path, long *mask) {
    static_assert(sizeof(*mask) * 8 >= EXT_TOTAL, "");

    char path_glob[MAX_PATH];
    int written = sprintf_s(path_glob, MAX_PATH, "%s\\*", path);
    if (written <= 0 || written >= MAX_PATH) return false;

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
        if (GetLastError() == ERROR_ACCESS_DENIED) return true;
        return false;
    }

    while (FindNextFileA(find, &fd)) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)) continue;

        char *ext = strrchr(fd.cFileName, '.');
        if (!ext) continue;
        ext++;

        for (int i = 0; i < EXT_TOTAL; ++i) {
            if (_bittest(mask, i)) continue;

            for (wchar_t j = 1; j <= *extensions[i][0]; ++j) {
                if (strcmp(ext, extensions[i][j]) == 0) {
                    _bittestandset(mask, i);
                    break;
                }
            }
        }
    }
    bool success = FindClose(find);
    assert(success);
    return false;
}


static bool set_valid_path(char *dest, const char *path)
{
    if (strlen(path) >= MAX_PATH)       return false;
    if (PathGetDriveNumberA(path) < 0)  return false;
    if (!PathFileExistsA(path))         return false;
    if (!PathCanonicalizeA(dest, path)) return false;

    PathRemoveBackslashA(dest);

    return true;
}

// This function ASSUMES valid utf8. The right return value should be size_t
// but this thing will run on DATA_CAPACITY max, which fits on u16
static unsigned short utf8len(const char *str) {
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


static void format_duration(char buf[7], unsigned duration) {
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


typedef struct {
    char path[MAX_PATH];
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


static bool remove_running_thread(const char *path, int64_t idx) {
    if (idx >= 0) {
        remove_running_thread_idx(idx);
        return true;
    }

    for (unsigned i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        assert(ti);
        // PERF: we compare by path for logging.
        // We should compare by handle for performance
        if (strcmp(path, ti->path)) continue;
        remove_running_thread_idx(i);
        return true;
    }

    return false;
}


static bool get_running_thread(const char *path, HANDLE *t) {
    assert(path != NULL);

    for (unsigned i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        assert(ti);
        if (strcmp(path, ti->path)) continue;

        DWORD code;
        bool ret = GetExitCodeThread(ti->handle, &code);
        assert(ret);

        if (code == STILL_ACTIVE) {
            *t = ti->handle;
            return true;
        } else {
            ret = remove_running_thread(path, i);
            assert(ret);
            return false;
        }

    }
    return false;
}


static bool append_running_thread(const char *path, HANDLE t) {
    ThreadItem ti;
    ti.handle = t;
    errno_t err = strncpy_s(ti.path, MAX_PATH, path, _TRUNCATE);
    assert(!err || err == STRUNCATE);

    bool ret = dynarr_append(&gitstatus_threads, &ti);
    assert(ret);
    return true;
}


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


// '?99999 +99999 m99999 x99999'
#define STATUS_SIZE 28
#define BRANCH_SIZE 20

// PERF: alignment
typedef struct {
    char *path;
    char branch[BRANCH_SIZE];
    char status[STATUS_SIZE];
} StatusItem;

typedef struct {
    git_repository *repo;
    char *path;
    HANDLE event;
} GSThreadParameter;


static bool changes_outside_dotgit(const char *buf) {
    while (1) {
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buf;

        if (
                // if FileName doesn't start with ".git"
                wcsstr(fni->FileName, L".git") != fni->FileName

                // except .git\HEAD
                && wcscmp(fni->FileName, L".git\\HEAD") != 0
            )
        { 
            return true;
        }

        if (!fni->NextEntryOffset) break;
        buf += fni->NextEntryOffset;
    }

    return false;
}


static HANDLE g_fsmon_thread = NULL;
static HANDLE g_fsmon_event = NULL;
static char *g_fsmon_path = NULL;

// PERF: linear search for long paths?
static DynArr status_cache;
static HANDLE g_status_cache_mutex = NULL;


static StatusItem *status_cache_get(const char *path) {
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    StatusItem *si = NULL;
    for (unsigned i = 0; i < status_cache.count; ++i) {
        StatusItem *test = dynarr_at(&status_cache, i);
        if (strcmp(test->path, path)) continue;
        si = test;
        break;
    }

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return si;
}

static bool status_cache_append(StatusItem *si) {
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    StatusItem *_si = dynarr_append(&status_cache, si);
    assert(_si != NULL);

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return true;
}

static bool status_cache_remove(const char *path) {
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    bool removed = false;
    for (unsigned i = 0; i < status_cache.count; ++i) {
        StatusItem *test = dynarr_at(&status_cache, i);
        if (strcmp(test->path, path)) continue;
        removed = dynarr_remove(&status_cache, i);
        assert(removed);
        break;
    }

    bool ret = ReleaseMutex(g_status_cache_mutex);
    assert(ret);

    return removed;
}


static bool fsmon_invalidate_idx(DynArr *events, DynArr *os, unsigned idx)
{
    OVERLAPPED *o = dynarr_at(os, idx);   assert(o != NULL);
    HANDLE *dir = dynarr_at(events, idx); assert(dir != NULL);

    char path[MAX_PATH];
    if (!GetFinalPathNameByHandleA(*dir, path, MAX_PATH, FILE_NAME_OPENED))
        return false;
    char *p = path + 4;  // "\\?\"

    bool removed = status_cache_remove(p);
    assert(removed);

    bool ret = CloseHandle(*dir);
    assert(ret);
    ret = dynarr_remove(events, idx);
    assert(ret);
    ret = dynarr_remove(os, idx);
    assert(ret);

    return true;
}


// Listen for changes on fs to invalidate StatusItem cache
static unsigned long fsmon_daemon_thread_proc(void *param) {
    DynArr events = dynarr_init_ex(sizeof(HANDLE), 4);
    DynArr os     = dynarr_init_ex(sizeof(OVERLAPPED), 4);
    dynarr_append(&events, &g_fsmon_event);
    dynarr_append_zeroed(&os); // The first event doesn't take an overlapped struct

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
            if (g_fsmon_path == NULL) {
                for (unsigned i = 0; i < events.count; ++i) {
                    HANDLE *h = dynarr_at(&events, i);
                    ret = CloseHandle(*h);
                    assert(ret);
                }
                dynarr_free(&events);
                dynarr_free(&os);
                break;
            }

            if (events.count == MAXIMUM_WAIT_OBJECTS)
                fsmon_invalidate_idx(&events, &os, 1);

            HANDLE dir = CreateFileA(
                    g_fsmon_path,
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    NULL);
            if (dir == INVALID_HANDLE_VALUE) return 1;

            OVERLAPPED *o = dynarr_append_zeroed(&os);
            assert(o != NULL);
            bool ret = ReadDirectoryChangesW(
                dir, changes, CHANGES_SIZE, true, filter, NULL, o, NULL);
            assert(ret);

            dynarr_append(&events, &dir);
            continue;
        }

        OVERLAPPED *o = dynarr_at(&os, idx);
        assert(o != NULL);
        HANDLE *dir = dynarr_at(&events, idx);
        assert(dir != NULL);

        unsigned long returned = 0;
        ret = GetOverlappedResult(*dir, o, &returned, false);
        assert(ret);  // if we waited on handle, `changes` must be ready

        if (returned && changes_outside_dotgit(changes)) {
            fsmon_invalidate_idx(&events, &os, idx);
            continue;
        }

        ret = ReadDirectoryChangesW(
            *dir, changes, CHANGES_SIZE, true, filter, NULL, o, NULL);
        assert(ret);
    }

    return 0;
}


#define WORK_BUF MAX_PATH

static unsigned long gitstatus_thread_proc(void *_tp) {
    GSThreadParameter *tp = _tp;
    git_repository *repo = tp->repo;
    char *path = tp->path;
    free(tp);

    StatusItem si = {0};

    // We don't use `git_repository_head` and the like because those show "what
    // is" and .git/HEAD shows "what will be if you perform a git action". Only
    // usefull before first git tree is created, maybe
    char buf[WORK_BUF];
    int written = snprintf(buf, WORK_BUF, "%s\\.git\\HEAD", path);
    if (written < 0 || written >= WORK_BUF) return 1;

    FILE *head = _fsopen(buf, "rt", _SH_DENYNO);
    if (head == NULL) goto branch_done;

    // ref: refs/heads/master
    // The first call will set `buf` to "ref:"
    int vars_set = fscanf_s(head, "%s", buf, WORK_BUF);
    if (vars_set <= 0) goto branch_done_close;

    // The second will set to "refs/heads/master". If head is only the hash,
    // this call will return 0 and buf will not be modified
    fscanf_s(head, "%s", buf, WORK_BUF);

    const char *branch;
    if (strstr(buf, "refs") == buf) {
        branch = strrchr(buf, '/') + 1;
    } else {
        buf[7] = 0;
        written = snprintf(buf + 8, WORK_BUF - 8, "detached at %s", buf);
        if (written <= 0 || written >= WORK_BUF - 8)
            goto branch_done_close;
        branch = buf + 8;
    }

    written = snprintf(si.branch, BRANCH_SIZE, "%s", branch);
    if (written <= 0) return 1;

    // Put ellipsis there to indicate that the branch is truncated
    if (written >= BRANCH_SIZE)
        for (int i = 1; i < 4; i++) si.branch[BRANCH_SIZE - i] = '.';

branch_done_close:
    fclose(head);
branch_done:

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
    int error = git_status_list_new(&statuses, repo, &opts);
    if (error) return 1;

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

    git_status_list_free(statuses);
    git_repository_free(repo);

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
        int written = snprintf(p, available, "%s%i", signs[i], values[i]);
        if (written < 0) return 1;

        if (written > available) {
            for (int i = 1; i < 4; i++)
                si.status[STATUS_SIZE - i] = '.';
            break;
        }
        p += written;
    }

    si.path = g_fsmon_path = path;

    static bool fsmon_created = false;
    if (!fsmon_created) {
        fsmon_created = true;
        g_fsmon_thread = CreateThread(NULL, 0, fsmon_daemon_thread_proc, NULL, 0, NULL);
        if (g_fsmon_thread == NULL) return 1;
    }
    if (!SetEvent(g_fsmon_event)) {
        printf("git thread could not set event for fsmon thread\n");
        return 1;
    }

    bool ret = status_cache_append(&si);
    assert(ret);

    return 0;
}



static bool set_status_item(StatusItem *si, const char *final_path)
{
    git_repository *repo = NULL;
    int error = git_repository_open(&repo, final_path);
    bool has_git = !error;
    if (!has_git) return false;

    StatusItem *_si = status_cache_get(final_path);
    if (_si != NULL) {
        *si = *_si;
        return true;
    }

    HANDLE thread = NULL;
    bool ret;
    if (!get_running_thread(final_path, &thread)) {
        // PERF: tp is mallocd here and freed on thread
        GSThreadParameter *tp = malloc(sizeof(GSThreadParameter));
        tp->repo = repo;
        tp->path = _strdup(final_path);
        thread = CreateThread(NULL, 0, gitstatus_thread_proc, tp, 0, NULL);
        ret = append_running_thread(final_path, thread);
        assert(ret);
    } else {  // either we give repo to thread or free it
        git_repository_free(repo);
    }
    assert(thread != NULL);

    DWORD wait = WaitForSingleObject(thread, GITSTATUS_TIMEOUT);
    switch (wait) {
        case WAIT_OBJECT_0:

            DWORD code;
            ret = GetExitCodeThread(thread, &code);
            assert(ret);

            int dont_know_index = -1;
            ret = remove_running_thread(final_path, dont_know_index);
            assert(ret);

            if (code != 0) {
                printf(
                    "-------\n"
                    "Thread exit code for %s is %lu\n"
                    "-------\n",
                    final_path, code);
                assert(0 && "Thread error");
                abort();
            }

            _si = status_cache_get(final_path);
            assert(_si != NULL);
            *si = *_si;

            break;

        case WAIT_TIMEOUT:
            break;

        case WAIT_FAILED:
        case WAIT_ABANDONED:
            assert(0 && "unreachable");
            abort();
    }

    return true;
}


typedef struct {
    char *text;
    unsigned len;
} Comp;

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


static bool handle_prompt(void) {
    unsigned short data_size = g_ctx->transfer.headers.data_size;
    g_ctx->transfer.headers.data_size = 0;
    if (data_size > sizeof(PromptData) + MAX_PATH - 3) return false;  // -3: \\*\0

    PromptData *pd = (PromptData *)g_ctx->transfer.data;
    int screen_width    = pd->screen_width;
    short error_code    = pd->error_code;
    unsigned cmd_dur_ms = pd->cmd_dur_ms;

    char final_path[MAX_PATH];
    if (!set_valid_path(final_path, pd->path)) return false;

    StatusItem si = {0};
    bool has_git = set_status_item(&si, final_path);

    long extmask = 0;
    bool access_denied = set_extensions(final_path, &extmask);

    const char *const userprofile = getenv("USERPROFILE");
    if (userprofile == NULL) return false;

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

        unsigned out_size = render_path.len - over + 1;  // size != len -> + 1
        BOOL b = PathCompactPathExA(buf, render_path.text, out_size, 0);
        assert(b);

        render_path.text = buf;
        left_size -= over;
    }
           
    assert(left_size + empty + right_size == screen_width);

    /// Now render everything
    push_color(SGR_BF_CYAN);
    push_text("\n%s %s", icon.text, render_path.text);

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

    // More thant 30k on each...
    // printf("available: dest: %i; tmp: %i\n", dest_available, tmp_available);

    return true;
}

#undef push_color
#undef push_text

#define MAX_REFPATH 30

typedef struct {
    char path[MAX_PATH];
    char refpath[MAX_REFPATH];
} PathItem;

static DynArr path_items;

static bool handle_refadd(void) {
    g_ctx->transfer.headers.data_size = 0;
    char *path = g_ctx->transfer.data;
    if (!path) return false;

    size_t pathlen = strlen(path);
    char *refpath = path + pathlen + 1;
    bool refpath_given = *refpath != 0;

    char final_path[MAX_PATH];
    if (!set_valid_path(final_path, path)) return false;

    // If path is just C, C:, or C:\ don't add
    if (!refpath_given) {
        char *last = strrchr(final_path, '\\');
        if (last == NULL) return false;
        refpath = last + 1;
        if (!*refpath) return false;
    }

    for (unsigned i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);
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

    dynarr_append(&path_items, &pi);

    return true;
}


static bool handle_refget(void) {
    g_ctx->transfer.headers.data_size = 0;
    char *refpath = g_ctx->transfer.data;
    if (!refpath) return false;

    for (unsigned i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);
        if (_stricmp(pi->refpath, refpath) == 0) {
            int written = sprintf(g_ctx->transfer.data, "%s", pi->path);
            g_ctx->transfer.headers.data_size = written + 1;
            return true;
        }
    }

    return false;
}


static bool handle_refdel(void) {
    g_ctx->transfer.headers.data_size = 0;
    char *what = g_ctx->transfer.data;
    bool is_refpath = *what++;

    char *target = what;
    char final_path[MAX_PATH];
    if (!is_refpath) {
        if (!set_valid_path(final_path, what)) return false;
        target = final_path;
    }

    for (unsigned i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);

        char *it = pi->path;
        if (is_refpath) it = pi->refpath;

        if (strcmp(it, target) == 0) {
            bool ret = dynarr_remove(&path_items, i);
            assert(ret);
            return true;
        }
    }

    return false;
}


static bool handle_refinc(void) {
    // TODO: Implement. 
    g_ctx->transfer.headers.data_size = 0;
    return false;
}


static bool handle_refgetall(void) {
    static_assert(sizeof(int) == 4 && INT32_MAX > DATA_CAPACITY, "");
    g_ctx->transfer.headers.data_size = 0;
    int written = 0;
    char *dest = g_ctx->transfer.data;
    *dest = 0;

    // It would take around 6k entries for this thing to not fit
    // into one transfer. After years of using this I'm at 91...
    for (unsigned i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);

        char *mask = "%s;";
        if (i == path_items.count - 1) mask = "%s";

        int it_written = snprintf(dest + written, DATA_CAPACITY - written, mask, pi->refpath);
        if (it_written < 0 || (unsigned)it_written > DATA_CAPACITY - written) return false;

        written += it_written;
    }

    written++;
    g_ctx->transfer.headers.data_size = written;
    return true;
}


#ifdef NDEBUG
int WinMain(HINSTANCE instance, HINSTANCE prev, LPSTR cmdline, int showcmd)
#else
int main(void)
#endif
{
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
    path_items        = dynarr_init(sizeof(PathItem));
    status_cache      = dynarr_init(sizeof(StatusItem));
    gitstatus_threads = dynarr_init(sizeof(ThreadItem));

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

            case MK_REFINC:
                success = handle_refinc();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFINC: %s\n", success ? "true" : "false");
                break;

            case MK_REFGETALL:
                success = handle_refgetall();
                g_ctx->transfer.headers.success = success;
                printf("MK_REFGETALL: %s\n", success ? "true" : "false");
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

        if (!dos) {
            if (!_ss_send()) return 1;
        }
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
        g_fsmon_path = NULL;
        ret = SetEvent(g_fsmon_event);
        assert(ret);

        wait = WaitForSingleObject(g_fsmon_thread, INFINITE);
        assert(wait == WAIT_OBJECT_0);
        ret = CloseHandle(g_fsmon_thread);
        assert(ret);
    }

    dynarr_free(&path_items);
    dynarr_free(&status_cache);
    dynarr_free(&gitstatus_threads);
    git_libgit2_shutdown();
    ss_shutdown();

    return 0;
}

#pragma comment(lib, "winhttp")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ole32")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "secur32")

#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <wchar.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <git2.h>

#define ARENA_IMPLEMENTATION
#define ARENA_SCOPE_STATIC
#include "arena.h"

#define DYNARR_IMPLEMENTATION
#define DYNARR_SCOPE_STATIC
#include "dynarr.h"

#define TERM_IMPLEMENTATION
#include "term.h"

#include "common.c"


#define GITSTATUS_TIMEOUT 300
#define CMD_DUR_THRESHOLD 200
#define FSMON_BUF_SIZE 1024


enum {
    HAS_C,
    HAS_CPP,
    EXT_TOTAL
};

#define MAX_EXT_STR_SIZE 4
// TODO: this size as first element is dumb
static wchar_t *extensions[EXT_TOTAL][MAX_EXT_STR_SIZE] = {
    [HAS_C]   = {L"\x02" , L"c", L"h"},
    [HAS_CPP] = {L"\x03" , L"cpp", L"hh", L"hpp"}
};

static char *extmapsign[EXT_TOTAL] = {
    [HAS_C]   = "",
    [HAS_CPP] = "",
};

static SetGraphicsRendition extmapcolor[EXT_TOTAL] = {
    [HAS_C]   = SGR_F_BLUE,
    [HAS_CPP] = SGR_F_BLUE
};


static void set_extensions(wchar_t *wide_path, long *mask) {
    static_assert(sizeof(*mask) * 8 >= EXT_TOTAL, "");

    errno_t err = wcscat_s(wide_path, MAX_PATH, L"\\*");
    assert(!err);
    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileExW(
            wide_path,
            FindExInfoBasic,
            &fd,
            FindExSearchNameMatch,
            NULL,
            FIND_FIRST_EX_LARGE_FETCH
    );
    if (find == INVALID_HANDLE_VALUE) return;

    while (FindNextFileW(find, &fd)) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)) continue;

        wchar_t *ext = wcsrchr(fd.cFileName, '.');
        if (!ext) continue;
        ext++;

        for (int i = 0; i < EXT_TOTAL; ++i) {
            if (_bittest(mask, i)) continue;

            for (wchar_t j = 1; j <= *extensions[i][0]; ++j) {
                if (wcscmp(ext, extensions[i][j]) == 0) {
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

// TODO: This method of reducing size of prompt in a loop is dumb
typedef enum {
    REDUCE_NOCLOCK = 1,
    REDUCE_SHRINKPATH,
    REDUCE_SHRINKPATH_AGAIN,
    REDUCE_ASTDIR,
    REDUCE_DOUBLEASTDIR,
    REDUCE_TOTAL
} ReduceMethod;

#define PATH_PIECE_TRESHOLD 17
#define PATH_BORDERS ((PATH_PIECE_TRESHOLD - 3) / 2)
static_assert(PATH_PIECE_TRESHOLD % 2 == 1, "");

static void shrink_path_piece(char *path) {
    // Microsoft.WindowsTerminal_8wekyb3d8bbwe
    // Microso...3d8bbwe
    // Check which part of the path is the biggest
    int biggest_piece, dir_sep, count, biggest_count;
    biggest_piece = dir_sep = count = biggest_count = 0;
    for (size_t i = 0; i < strlen(path); ++i) {
        if (path[i] == '\\') {
            if (count > biggest_count) {
                biggest_piece = dir_sep;
                biggest_count = count;
            }
            dir_sep++;
            count = 0;
            continue;
        }
        count++;
    }

    if (biggest_count > PATH_PIECE_TRESHOLD) {
        char *p = path;
        for (int i = 0; i < biggest_piece; ++i) {
            p = strchr(p, '\\');
            assert(p != NULL);
            p++;
        }

        const char *op = path + (size_t)p - (size_t)path + biggest_count - PATH_BORDERS;
        p += PATH_BORDERS;
        memset(p, '.', 3);
        p += 3;
        int written = sprintf(p, "%s", op);
        assert(written > 0);
    }
}


static void asterisk_dir(char *path) {
    int count = 0;
    for (size_t i = 0; i < strlen(path); ++i) {
        if (path[i] == '\\') count++;
    }

    int idx = count / 2;
    char *p = path;
    for (int i = 0; i < idx; ++i) {
        p = strchr(p, '\\');
        assert(p != NULL);
        p++;
    }

    const char *op = strchr(p, '\\');
    assert(op != NULL);
    *p++ = '*';
    int written = sprintf(p, "%s", op);
    assert(written > 0);
}


static void double_ast_dir(char *path) {
    char *ast = strchr(path, '*'); assert(ast);
    
    char *p = ast;
    for (int i = 0; i < 3; ++i) {
        p = strchr(p, '\\');
        if (p == NULL) return;
        p++;
    }

    ast++; *ast = '*'; ast++;
    int written = sprintf(ast, "%s", --p);
    assert(written > 0);
}


static void format_path(char *path, ReduceMethod rm) {
    assert(rm != REDUCE_NOCLOCK);

    shrink_path_piece(path);
    if (rm <= REDUCE_SHRINKPATH) return;

    shrink_path_piece(path);
    if (rm <= REDUCE_SHRINKPATH_AGAIN) return;

    asterisk_dir(path);
    if (rm <= REDUCE_ASTDIR) return;

    double_ast_dir(path);
    if (rm <= REDUCE_DOUBLEASTDIR) return;

    assert(0 && "Unreachable");
}


typedef struct {
    char *path;
    HANDLE handle;
} ThreadItem;

static DynArr gitstatus_threads;

static bool remove_running_thread(const char *path) {
    // PERF: we compare by path for logging.
    // We should compare by handle for performance
    for (size_t i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        if (strcmp(path, ti->path)) continue;
        // TODO: this was allocd below on _strdup,
        // `path` should be a buffer on ThreadItem.
        free(ti->path);
        bool ret = CloseHandle(ti->handle);
        assert(ret);
        return dynarr_remove(&gitstatus_threads, i);
    }

    return false;
}


static bool get_running_thread(const char *path, HANDLE *t) {
    assert(path != NULL);

    for (size_t i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        if (ti->path == NULL || strcmp(path, ti->path)) continue;
        DWORD code;
        bool ret = GetExitCodeThread(ti->handle, &code);
        assert(ret);

        if (code == STILL_ACTIVE) {
            *t = ti->handle;
            return true;
        } else {
            ret = remove_running_thread(path);
            assert(ret);
            return false;
        }

    }
    return false;
}


static bool append_running_thread(const char *path, HANDLE t) {
    // TODO: remove those _strdup
    for (size_t i = 0; i < gitstatus_threads.count; ++i) {
        ThreadItem *ti = dynarr_at(&gitstatus_threads, i);
        if (ti->path != NULL) continue;
        ti->path = _strdup(path);
        ti->handle = t;
        return true;
    }

    ThreadItem ti = {
        .path = _strdup(path),
        .handle = t
    };
    dynarr_append(&gitstatus_threads, &ti);
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
#define BRANCH_SIZE 30

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


static WCHAR action_names[][29] = {
    [FILE_ACTION_ADDED]            = L"ADDED",
    [FILE_ACTION_REMOVED]          = L"REMOVED",
    [FILE_ACTION_MODIFIED]         = L"MODIFIED",
    [FILE_ACTION_RENAMED_OLD_NAME] = L"RENAMED_OLD_NAME",
    [FILE_ACTION_RENAMED_NEW_NAME] = L"RENAMED_NEW_NAME",
};

static bool changes_outside_dotgit(const char *buf, FILE *file) {
    while (1) {
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buf;
        fwprintf(file, L"%.*s %s\n", fni->FileNameLength/2, fni->FileName, action_names[fni->Action]);

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
static char *g_fsmon_path = NULL;

// PERF: linear search for long paths?
static DynArr status_cache;
static HANDLE g_status_cache_mutex = NULL;
static Arena  status_paths = {0};


static StatusItem *status_cache_get(const char *path) {
    DWORD wait = WaitForSingleObject(g_status_cache_mutex, INFINITE);
    assert(wait == WAIT_OBJECT_0);

    StatusItem *si = NULL;
    for (size_t i = 0; i < status_cache.count; ++i) {
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
    for (size_t i = 0; i < status_cache.count; ++i) {
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


static unsigned long fsmon_thread_proc(void *param) {
    HANDLE event = (HANDLE)param;

    DynArr events = dynarr_init(sizeof(HANDLE));
    dynarr_append(&events, &event);
    DynArr os = dynarr_init(sizeof(OVERLAPPED));
    // Wastes memory but align for idx
    dynarr_append_zeroed(&os);

    // TODO: Remove fsmon logging
    FILE *file = _fsopen("thread_out.txt", "wb+", _SH_DENYNO);
    if (file == NULL) return 1;

    fprintf(file, "thread output init\n"); fflush(file);

    DWORD filter = 
        FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        // | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION
        ;

    char buf[FSMON_BUF_SIZE];
    while (1) {
        unsigned long idx = WaitForMultipleObjects((DWORD)events.count, events._data, false, INFINITE);
        if (idx >= events.count) return 1;

        if (idx == 0) {
            if (g_fsmon_path == NULL) {
                fprintf(file, "closing output file\n"); fflush(file);
                fclose(file);

                for (size_t i = 0; i < events.count; ++i) {
                    HANDLE *h = dynarr_at(&events, i);
                    bool ret = CloseHandle(*h);
                    assert(ret);
                }
                dynarr_free(&events);
                dynarr_free(&os);
                break;
            }

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
            bool ret = ReadDirectoryChangesW(dir, buf, FSMON_BUF_SIZE, true, filter, NULL, o, NULL);
            assert(ret);

            dynarr_append(&events, &dir);

            fprintf(file, "listening for changes on %s\n", g_fsmon_path); fflush(file);
            continue;
        }

        OVERLAPPED *o = dynarr_at(&os, idx);
        assert(o != NULL);
        HANDLE *dir = dynarr_at(&events, idx);
        assert(dir != NULL);

        unsigned long returned = 0;
        bool ret = GetOverlappedResult(*dir, o, &returned, false);
        assert(ret);

        bool stop_mon = true;
        if (returned) {
            stop_mon = changes_outside_dotgit(buf, file); fflush(file);
        }

        if (stop_mon) {
            char path[MAX_PATH];
            if (!GetFinalPathNameByHandleA(*dir, path, MAX_PATH, FILE_NAME_OPENED)) return 1;
            char *p = path + 4;  // "\\?\"

            bool removed = status_cache_remove(p);
            assert(removed);

            ret = CloseHandle(*dir);
            assert(ret);
            ret = dynarr_remove(&events, idx);
            assert(ret);
            ret = dynarr_remove(&os, idx);
            assert(ret);

            continue;
        }

        ret = ReadDirectoryChangesW(*dir, buf, FSMON_BUF_SIZE, true, filter, NULL, o, NULL);
        assert(ret);
    }

    return 0;
}


static unsigned long gitstatus_thread_proc(void *_tp) {
    GSThreadParameter *tp = _tp;
    git_repository *repo = tp->repo;
    char *path = tp->path;
    HANDLE event = tp->event;
    free(tp);

    StatusItem si = {0};

    // We don't use `git_repository_head` and the like because those show "what is"
    // and .git/HEAD shows "what will be if you perform a git action". Only
    // usefull before first git tree is created
    char buf[MAX_PATH];
    int written = snprintf(buf, MAX_PATH, "%s\\.git\\HEAD", path);
    if (written < 0 || written > MAX_PATH) return 1;

    FILE *head = _fsopen(buf, "rt", _SH_DENYNO);
    if (head == NULL) return 1;

    // ref: refs/heads/master
    // The first call will set `buf` to "ref:"
    fscanf_s(head, "%s", buf, MAX_PATH);

    // The second will set to "refs/heads/master"
    fscanf_s(head, "%s", buf, MAX_PATH);

    // For some reason `fscanf_s` still returns full string on second call if
    // file content is only the hash, so we check if head is detached by
    // comparing the start of string
    const char *branch;
    if (strstr(buf, "refs") == buf) {
        branch = strrchr(buf, '/') + 1;
    } else {
        buf[7] = 0;
        written = snprintf(buf + 8, MAX_PATH - 8, "detached at %s", buf);
        if (written <= 0 || written > MAX_PATH - 8) return 1;
        branch = buf + 8;
    }

    written = snprintf(si.branch, BRANCH_SIZE, "%s", branch);
    if (written <= 0 || written > BRANCH_SIZE) return 1;

    fclose(head);

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
        if (values[i]) {

            if (*si.status) { *p = ' '; p++; }
            size_t available = STATUS_SIZE - ((size_t)p - (size_t)si.status);
            int written = snprintf(p, available, "%s%i", signs[i], values[i]); 
            if (written < 0 || written > available) return 1;

            p += written;
        }
    }

    si.path = g_fsmon_path = path;

    static bool fsmon_created = false;
    if (!fsmon_created) {
        fsmon_created = true;
        g_fsmon_thread = CreateThread(NULL, 0, fsmon_thread_proc, event, 0, NULL);
        if (g_fsmon_thread == NULL) return 1;
    }
    if (!SetEvent(event)) {
        printf("git thread could not set event for fsmon thread\n");
        return 1;
    }

    bool ret = status_cache_append(&si);
    assert(ret);

    return 0;
}



#define push_color(color) do {            \
    written = term_buf_sgr(dest, color);  \
    dest += written;                      \
    dest_available -= written;            \
} while(0)

#define push_text(...) do {                                 \
    written = snprintf(dest, dest_available, __VA_ARGS__);  \
    left_size += utf8len(dest);                             \
    dest += written;                                        \
    dest_available -= written;                              \
} while (0)


static bool handle_prompt(HANDLE event) {
    unsigned short data_size = g_ctx->transfer.headers.data_size;
    g_ctx->transfer.headers.data_size = 0;
    if (data_size > sizeof(PromptData) + MAX_PATH - 3) return false;  // -3: \\*\0

    PromptData *pd = (PromptData *)g_ctx->transfer.data;
    int screen_width    = pd->screen_width;
    short error_code    = pd->error_code;
    unsigned cmd_dur_ms = pd->cmd_dur_ms;

    char orig_path[MAX_PATH];
    strcpy(orig_path, pd->path);
    size_t path_len = strlen(orig_path);

    wchar_t wide_path[MAX_PATH];
    size_t converted = mbstowcs(wide_path, orig_path, path_len + 1);
    if (converted != path_len) return false;

    unsigned long ret = GetFileAttributesW(wide_path);
    if (ret == INVALID_FILE_ATTRIBUTES || !(ret & FILE_ATTRIBUTE_DIRECTORY)) return false;

    git_repository *repo = NULL;
    int error = git_repository_open(&repo, orig_path);
    bool has_git = !error;
    StatusItem si = {0};

    if (has_git) {

        bool cached = false;
        StatusItem *_si = status_cache_get(orig_path);
        if (_si != NULL) {
            cached = true;
            si = *_si;
        }

        if (!cached) {
            HANDLE thread = NULL;
            if (!get_running_thread(orig_path, &thread)) {
                GSThreadParameter *tp = malloc(sizeof(GSThreadParameter));
                tp->repo = repo;
                tp->path = arena_strdup(&status_paths, orig_path);
                tp->event = event;
                thread = CreateThread(NULL, 0, gitstatus_thread_proc, tp, 0, NULL);
                bool ret = append_running_thread(orig_path, thread);
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

                    bool ret = remove_running_thread(orig_path);
                    assert(ret);

                    if (code != 0) printf(
                            "-------\n"
                            "Thread exit code for %s is %lu\n"
                            "-------\n",
                            orig_path, code);

                    if (code == 0) {
                        _si = status_cache_get(orig_path);
                        assert(_si != NULL);
                        si = *_si;
                    }
                    break;

                case WAIT_TIMEOUT:
                    break;
                case WAIT_FAILED:
                case WAIT_ABANDONED:
                    assert(0 && "unreachable");
                    abort();
            }
        }
    }

    long extmask = 0;
    set_extensions(wide_path, &extmask);

    const char *const userprofile = getenv("USERPROFILE");
    if (userprofile == NULL) return false;

    int reduce_method = 0;
    while (reduce_method < REDUCE_TOTAL) {
        // My screen (pretty regular one) with regular font size has 168 columns
        // some gigantic screens might have, what? triple that?
        // Feels dumb to alloc more when we have lots of unused space in
        // g_ctx.transfer.data (DATA_CAPACITY: 65507 - headers)
        int tmp_available, dest_available, written;
        tmp_available = dest_available = DATA_CAPACITY / 2;
        char *tmp = g_ctx->transfer.data + tmp_available;
        char *dest = g_ctx->transfer.data;

        // Right portion. Save to temp first bc I need to know its size
        int right_size = 0;
        char *duration = "";
        if (cmd_dur_ms > CMD_DUR_THRESHOLD) {
            char buf[7] = {0};
            format_duration(buf, cmd_dur_ms);
            written = snprintf(tmp, tmp_available, " %s", buf);
            right_size += utf8len(tmp);
            duration = tmp;
            tmp += written + 1;
            tmp_available -= written + 1;
        }

        char *clock = "";
        if (reduce_method < REDUCE_NOCLOCK) {
            time_t t;
            struct tm timeinfo;
            time(&t);
            errno_t err = localtime_s(&timeinfo, &t);
            assert(!err);

            int h, m, s;
            h = timeinfo.tm_hour;
            m = timeinfo.tm_min;
            s = timeinfo.tm_sec;

            char *ptr = tmp;
            bool has_duration = false;
            if (*duration) {
                has_duration = true;
                *ptr = ' ';
                ptr++;
            }
            // TODO: the clock in my font is rendered on two columns, so '+ 1' on utf8len.
            // Check if it happens with other fonts
            written = snprintf(ptr, tmp_available, "🕓 %02i:%02i:%02i", h, m, s);
            right_size += utf8len(tmp) + 1;
            clock = tmp;
            tmp += written + 1 + has_duration;
            tmp_available -= written + 1 - has_duration;
        }

        char path[MAX_PATH];
        strcpy(path, orig_path);

        char *path_icon = "";
        if (strcmp(userprofile, path) == 0) path_icon = "";
        // TODO: else ... 

        int left_size = 0;
        push_color(SGR_BF_CYAN);
        push_text("\n%s ", path_icon);
        left_size--;  // new line

        char *render_path = path;
        char *test = strstr(path, userprofile);
        if (test == path) {  // if starts with `userprofile`
            render_path = path + strlen(userprofile) - 1;
            *render_path = '~';
        }
        if (reduce_method >= REDUCE_SHRINKPATH) format_path(render_path, reduce_method);
        push_color(SGR_BF_CYAN);
        push_text("%s", render_path);

        if (has_git) {
            push_color(SGR_BF_RED);
            push_text("  ");

            if (*si.branch) {  // if completed. branch is mandatory
                push_color(SGR_DEFAULT);
                push_text("[");
                    push_color(SGR_BF_MAGENTA);
                    push_text(" %s", si.branch);
                push_color(SGR_DEFAULT);
                push_text("]");

                if (*si.status) {
                    push_text(" [");
                        push_color(SGR_BF_RED);
                        push_text("%s", si.status);
                    push_color(SGR_DEFAULT);
                    push_text("]");
                }

            } else {
                push_color(SGR_DEFAULT);
                push_text("[");
                    push_color(SGR_BF_RED);
                    push_text("...");
                push_color(SGR_DEFAULT);
                push_text("]");
            }
        }

        for (int i = 0; i < EXT_TOTAL; ++i) {
            if (_bittest(&extmask, i)) {
                push_color(extmapcolor[i]);
                push_text(" %s", extmapsign[i]);
            }
        }

        int spaces;
        if      (left_size <  screen_width) spaces = screen_width - right_size - left_size;
        else if (left_size == screen_width) spaces = 0;
        else   /*left_size > screen_width*/ spaces = 1; 
        push_text("%*s", spaces, "");

        bool overflow = screen_width < right_size + left_size;

        // Render right_portion
        push_color(SGR_DEFAULT);
        push_text("%s", duration);
        push_text("%s", clock);

        // ❯
        push_color(error_code ? SGR_BF_RED : SGR_BF_GREEN);
        if (overflow) push_text("%s", " ");
        push_text("%s", "❯ ");
        push_color(SGR_DEFAULT);

        assert(dest_available >= 0);
        g_ctx->transfer.headers.data_size = DATA_CAPACITY / 2 - (unsigned short)dest_available + 1;

        // printf("available: dest: %i; tmp: %i\n", dest_available, tmp_available);
        if (!overflow) break;
        reduce_method++;
    }

    return true;
}

#undef push_color
#undef push_text

typedef struct {
    char *path;
    char *refpath;
    int priority;
} PathItem;

static DynArr path_items;
static Arena path_items_arena = {0};

static bool handle_refadd(void) {
    g_ctx->transfer.headers.data_size = 0;
    char *path = g_ctx->transfer.data;
    if (!path) return false;

    size_t pathlen = strlen(path);
    char *refpath = path + pathlen + 1;

    while (path[pathlen - 1] == '\\') path[pathlen-- - 1] = '\0';
    char *end = strrchr(path, '\\');

    // If path is just C, C:, or C:\ don't add
    if (end == NULL) return false;

    if (*refpath == 0) {
        // It would take 393216PB of memory for `i` to wrap
        for (size_t i = 0; i < path_items.count; ++i) {
            PathItem *pi = dynarr_at(&path_items, i);
            if (pi->path && strcmp(pi->path, path) == 0) return false;
        }
        refpath = end + 1;
    }

    PathItem pi = {
        arena_strdup(&path_items_arena, path),
        arena_strdup(&path_items_arena, refpath),
        0
    };
    dynarr_append(&path_items, &pi);

    return true;
}


static bool handle_refget(void) {
    g_ctx->transfer.headers.data_size = 0;
    char *refpath = g_ctx->transfer.data;
    if (!refpath) return false;

    for (size_t i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);
        if (pi->path && _stricmp(pi->refpath, refpath) == 0) {
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

    size_t len = strlen(what);
    while (what[len - 1] == '\\') what[len-- - 1] = '\0';

    for (size_t i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);
        if (pi->path == NULL) continue;

        char *target = pi->path;
        if (is_refpath) target = pi->refpath;
        if (strcmp(what, target) == 0) {
            pi->path = NULL;
            pi->refpath = NULL;
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

    // It would take around 6k entries for this thing to not fit
    // into one transfer. After years of using this I'm at 91...
    for (size_t i = 0; i < path_items.count; ++i) {
        PathItem *pi = dynarr_at(&path_items, i);
        if (pi->path == NULL) continue;

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


int main(void) {
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
    HANDLE event  = CreateEventW(NULL, false, false, NULL);
    if (event == INVALID_HANDLE_VALUE) return 1;

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
                bool success = handle_prompt(event);
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

    bool ret;
    DWORD wait;
    for (size_t i = 0; i < gitstatus_threads.count; ++i) {
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

    // This is how we tell fsmon thread to shutdown
    g_fsmon_path = NULL;
    ret = SetEvent(event);
    assert(ret);

    wait = WaitForSingleObject(g_fsmon_thread, INFINITE);
    assert(wait == WAIT_OBJECT_0);
    ret = CloseHandle(g_fsmon_thread);
    assert(ret);

    // fsmon will close this handle on cleanup
    // ret = CloseHandle(event);

    dynarr_free(&path_items);
    dynarr_free(&status_cache);
    dynarr_free(&gitstatus_threads);
    arena_free(&status_paths);
    arena_free(&path_items_arena);
    git_libgit2_shutdown();
    ss_shutdown();

    return 0;
}

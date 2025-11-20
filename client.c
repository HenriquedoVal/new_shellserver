///

#include "client.h"

#include "common.c"

// TODO: handle if return from server is not the same kind we gave to it. Not
// all function are exactly reentrant so we can't just call them again


/// Static

static bool IsUserAdmin(void)
{
    BOOL ret;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID adm_group;

    ret = AllocateAndInitializeSid(
        &nt,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adm_group);

    if (ret) {
        if (!CheckTokenMembership(NULL, adm_group, &ret))
            ret = FALSE;
        FreeSid(adm_group);
    }

    return ret;
}


static bool g_admin = false;

static bool client_init(void)
{
    if (g_ctx == NULL && !ss_init()) return false;

    static bool queried_if_admin = false;
    if (!queried_if_admin) {
        if (IsUserAdmin()) g_admin = true;
        queried_if_admin = true;
    }

    return true;
}


static bool del_path_or_refpath(bool is_refpath, const char *what)
{
    if (!client_init()) return false;

    if (what == NULL) return false;
    size_t whatlen = strlen(what);
    if (is_refpath && whatlen > MAX_PATH) return false;
    if (!is_refpath && whatlen > DATA_CAPACITY - 1) return false;

    char *dest = g_ctx->transfer.data;
    *dest++ = is_refpath;
    int written = snprintf(dest, DATA_CAPACITY - 1, "%s", what);
    if (written < 0) return false;
    written += 2;  // is_refpath + \0

    g_ctx->transfer.headers.kind = MK_REFDEL;
    g_ctx->transfer.headers.data_size = written;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}


static bool no_arg_returns_success(enum MESSAGE_KIND mk)
{
    if (!client_init()) return false;

    g_ctx->transfer.headers.kind = mk;
    g_ctx->transfer.headers.data_size = 0;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}


static const char *no_arg_returns_data(enum MESSAGE_KIND mk)
{
    if (!client_init()) return NULL;

    g_ctx->transfer.headers.kind = mk;
    g_ctx->transfer.headers.data_size = 0;

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


static const char *charptr_returns_data(enum MESSAGE_KIND mk, const char *arg)
{
    if (!client_init()) return false;

    if (arg == NULL) return false;
    size_t len = strlen(arg);
    if (len >= DATA_CAPACITY) return false;

    int written = sprintf(g_ctx->transfer.data, "%s", arg);
    if (written <= 0 || written >= DATA_CAPACITY) return false;

    written++;
    g_ctx->transfer.headers.kind = mk;
    g_ctx->transfer.headers.data_size = written;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


/// Exports

#ifndef NDEBUG
__declspec(dllexport) void _set_port(short port) { g_port = port; }
#endif

bool ss_add_refpath(const char *path, /*nullable*/ const char *as)
{
    if (!client_init()) return false;

    if (path == NULL) return false;
    size_t pathlen = strlen(path);
    if (pathlen > MAX_PATH) return false;
    if (as != NULL && !*as) return false;

    if (as == NULL) as = "";

    char *dest = g_ctx->transfer.data;
    int path_written = snprintf(dest, DATA_CAPACITY, "%s", path);
    if (path_written < 0 || (unsigned)path_written >= MAX_PATH) return false;
    path_written++;  // \0

    int as_written = snprintf(dest + path_written, DATA_CAPACITY - path_written, "%s", as);
    if (as_written < 0 || (unsigned)as_written >= DATA_CAPACITY - path_written) return false;
    as_written++;

    g_ctx->transfer.headers.kind = MK_REFADD;
    g_ctx->transfer.headers.data_size = path_written + as_written;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}


bool ss_del_refpath(const char *refpath)
{
    return del_path_or_refpath(true, refpath);
}


bool ss_del_refpath_by_path(const char *path)
{
    return del_path_or_refpath(false, path);
}


bool ss_move_refpath_down(const char *refpath)
{
    // charptr_returns_success...
    if (!client_init()) return false;

    if (refpath == NULL) return false;
    size_t len = strlen(refpath);
    if (len >= DATA_CAPACITY) return false;

    int written = sprintf(g_ctx->transfer.data, "%s", refpath);
    written++;
    g_ctx->transfer.headers.kind = MK_MVREFDOWN;
    g_ctx->transfer.headers.data_size = written;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}


bool ss_kill_server(void)
{
    return no_arg_returns_success(MK_QUIT);
}


bool ss_save_cache(void)
{
    return no_arg_returns_success(MK_SAVE);
}


const char *ss_get_prompt(
    const char *path, short term_width, int error_code, unsigned cmd_dur_ms)
{
    if (!client_init()) return NULL;

    if (path == NULL) return NULL;
    size_t path_size = strlen(path) + 1;
    if (path_size > MAX_PATH) return NULL;

    char *admin = "(Admin) ";
    char *data = g_ctx->transfer.data;

    PromptData *pd = (PromptData *)data;
    Headers *h = (Headers *)&g_ctx->transfer.headers;

    pd->screen_width = term_width - (int)g_admin * strlen(admin);
    pd->error_code = error_code;
    pd->cmd_dur_ms = cmd_dur_ms;
    strcpy(pd->path, path);

    h->kind = MK_PROMPT;
    h->data_size = (unsigned short)(sizeof(PromptData) + path_size);

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;

    unsigned there = h->data_size;
    char *dest = data + there;
    char *ptr = dest;

    char *hide_cursor = "\x1b[?25l";
    char *show_cursor = "\x1b[?25h";

    int available = (int)(DATA_CAPACITY - there);
    int w = snprintf(ptr, available, "%s\n", hide_cursor);
    if (w <= 0 || w >= available) return NULL;
    available -= w;
    ptr += w;

    if (g_admin) {
        w = snprintf(ptr, available, "\x1b[31m%s\x1b[0m", admin);
        if (w <= 0 || w >= available) return NULL;
        available -= w;
        ptr += w;
    }

    w = snprintf(ptr, available, "%s%s", data, show_cursor);
    if (w <= 0 || w >= available) return NULL;
    available -= w;
    ptr += w;

    assert(available >= 0);

    return dest;
}


const char *ss_echo(const char *msg)
{
    return charptr_returns_data(MK_ECHO, msg);
}


const char *ss_get_path(const char *refpath)
{
    return charptr_returns_data(MK_REFGET, refpath);
}


const char *ss_get_all_refpaths(void)
{
    return no_arg_returns_data(MK_REFGETALL);
}


const char *ss_get_cache_memory_state(void)
{
    return no_arg_returns_data(MK_DUMP_MEM);
}


const char *ss_get_cache_stored_state(void)
{
    return no_arg_returns_data(MK_DUMP_DISK);
}

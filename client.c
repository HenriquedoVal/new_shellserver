#include "client.h"

#include "common.c"


static_assert(MAX_UDP > sizeof(PromptData) + MAX_PATH, "");

// TODO: handle if return from server is not the same kind we gave to it. Not
// all function are exactly reentrant so we can't just call them again

const char *ss_get_prompt(
    const char *path, short term_width, int error_code, unsigned cmd_dur_ms)
{
    if (g_ctx == NULL && !ss_init()) return NULL;

    if (path == NULL) return NULL;
    size_t path_size = strlen(path) + 1;
    if (path_size > MAX_PATH) return NULL;

    PromptData *pd = (PromptData *)g_ctx->transfer.data;
    Headers *h = (Headers *)&g_ctx->transfer.headers;

    pd->screen_width = term_width;
    pd->error_code = error_code;
    pd->cmd_dur_ms = cmd_dur_ms;
    strcpy(pd->path, path);

    h->kind = MK_PROMPT;
    h->data_size = (unsigned short)(sizeof(PromptData) + path_size);

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


const char *ss_echo(const char *msg)
{
    if (g_ctx == NULL && !ss_init()) return NULL;

    if (msg == NULL) return NULL;
    size_t len = strlen(msg);
    if (len > DATA_CAPACITY) return NULL;

    g_ctx->transfer.headers.kind = MK_ECHO;
    g_ctx->transfer.headers.data_size = (unsigned short)len + 1;
    strcpy(g_ctx->transfer.data, msg);

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


bool ss_kill_server(void)
{
    if (g_ctx == NULL && !ss_init()) return false;

    g_ctx->transfer.headers.kind = MK_QUIT;
    g_ctx->transfer.headers.data_size = 0;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}


bool ss_add_refpath(const char *path, /*nullable*/ const char *as)
{
    if (g_ctx == NULL && !ss_init()) return false;

    if (path == NULL) return false;
    size_t pathlen = strlen(path);
    if (pathlen > MAX_PATH) return false;
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


static bool del_path_or_refpath(bool is_refpath, const char *what)
{
    if (g_ctx == NULL && !ss_init()) return false;

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


bool ss_del_refpath(const char *refpath)
{
    return del_path_or_refpath(true, refpath);
}


bool ss_del_refpath_by_path(const char *path)
{
    return del_path_or_refpath(false, path);
}


const char *ss_get_path(const char *refpath)
{
    if (g_ctx == NULL && !ss_init()) return NULL;

    if (refpath == NULL) return NULL;
    size_t size = strlen(refpath);
    if (size >= DATA_CAPACITY) return NULL;

    int written = sprintf(g_ctx->transfer.data, "%s", refpath);
    if (written < 0) return false;
    written++;
    g_ctx->transfer.headers.kind = MK_REFGET;
    g_ctx->transfer.headers.data_size = written;

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


const char *ss_get_all_refpaths(void)
{
    if (g_ctx == NULL && !ss_init()) return NULL;

    g_ctx->transfer.headers.kind = MK_REFGETALL;
    g_ctx->transfer.headers.data_size = 0;

    if (!_ss_send()) return NULL;
    if (!_ss_recv()) return NULL;

    if (!g_ctx->transfer.headers.success) return NULL;
    return g_ctx->transfer.data;
}


bool ss_inc_refpath_priority(const char *path)
{
    if (g_ctx == NULL && !ss_init()) return false;

    if (path == NULL) return false;
    size_t size = strlen(path);
    if (size >= DATA_CAPACITY) return false;

    int written = sprintf(g_ctx->transfer.data, "%s", path);
    written++;
    g_ctx->transfer.headers.kind = MK_REFINC;
    g_ctx->transfer.headers.data_size = written;

    if (!_ss_send()) return false;
    if (!_ss_recv()) return false;
    assert(g_ctx->transfer.headers.data_size == 0);

    return g_ctx->transfer.headers.success;
}

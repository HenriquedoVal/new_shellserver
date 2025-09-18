#pragma once

#define COMMON_CLIENT_SIDE
#include "common.h"


// __declspec(dllexport) bool ss_register(const char *client);
// __declspec(dllexport) bool ss_set_config_local(enum? config, int? value);
// __declspec(dllexport) bool ss_set_config_global(enum? config, int? value);

__declspec(dllexport) bool ss_del_refpath(const char *refpath);
__declspec(dllexport) bool ss_del_refpath_by_path(const char *path);
__declspec(dllexport) bool ss_inc_refpath_priority(const char *path);
__declspec(dllexport) bool ss_kill_server(void);
__declspec(dllexport) bool ss_add_refpath(
        const char *path, /*nullable*/ const char *as);

__declspec(dllexport) const char *ss_echo(const char *msg);
__declspec(dllexport) const char *ss_get_path(const char *refpath);
__declspec(dllexport) const char *ss_get_all_refpaths(void);
__declspec(dllexport) const char *ss_get_prompt(
        const char *path, short term_width, int error_code, unsigned cmd_dur_ms);

__declspec(dllexport) void ss_shutdown(void);

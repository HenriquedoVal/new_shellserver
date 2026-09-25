#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <stdbool.h>

#include <winsock2.h>

#define PORT 10101

enum MESSAGE_KIND {
    MK_ECHO,
    MK_PROMPT,
    MK_QUIT,
    MK_REFADD,
    MK_REFGET,
    MK_REFDEL,
    MK_MVREFDOWN,
    MK_REFGETALL,
    MK_DUMP_MEM,
    MK_DUMP_DISK,
    MK_SAVE,
    MK_CONFIG
};

typedef struct {
    char magic[4];
    unsigned char kind;
    bool success;
    unsigned short data_size;
} Headers;

typedef struct {
    SOCKET sock;
    struct sockaddr_in addr;
    struct {
        Headers headers;
        char data[];
    } transfer;
} Context;

#define MAX_UDP 65507
#define HEADERS_SIZE_AND_PAD (offsetof(Context, transfer.data) - offsetof(Context, transfer.headers))
#define DATA_CAPACITY (MAX_UDP - HEADERS_SIZE_AND_PAD)

typedef struct {
    short screen_width;  // not unsigned bc Windows sets this way
    int error_code;
    unsigned cmd_dur_ms;
    char path[];
} PromptData;

static_assert(MAX_UDP > sizeof(PromptData) + MAX_PATH, "");

typedef enum {
    SS_CONFIG_DISABLE = -1,
    SS_CONFIG_KEEP,
    SS_CONFIG_ENABLE
} SSUpdateConfigValue;

// Ensure they have the same field names
#define SS_TYPEDEF_STRUCT_CONFIG(Name, type_t) \
typedef struct {                               \
    type_t show_git_info;                      \
    type_t show_extension_icons;               \
    type_t show_cmd_duration;                  \
    type_t show_battery;                       \
    type_t show_clock;                         \
} Name

SS_TYPEDEF_STRUCT_CONFIG(SSConfig, bool);
SS_TYPEDEF_STRUCT_CONFIG(SSUpdateConfig, SSUpdateConfigValue);

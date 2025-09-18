#pragma once

#define _CRT_SECURE_NO_WARNINGS
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
    MK_REFINC,
    MK_REFGETALL
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

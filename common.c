#pragma comment(lib, "ws2_32.lib")

#include <assert.h>
#include <stdio.h>

#include <winsock2.h>

#include "common.h"

#define SS_TIMEOUT_MS 1000

static short g_port = PORT;
static const char g_transfer_magic[4] = {'S', 'c', 'S', 'h'};
static Context *g_ctx = NULL;

static struct sockaddr_in get_server_addr(void) {
    unsigned char localhost[4] = {127, 0, 0, 1};
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_port),
        .sin_addr.s_addr = *(unsigned *)&localhost
    };
    return server_addr;
}


static bool _ss_send(void) {
    unsigned short data_size = g_ctx->transfer.headers.data_size;
    if (data_size > DATA_CAPACITY) return true;

    int sent = sendto(
            g_ctx->sock,
            (char *)&g_ctx->transfer,
            HEADERS_SIZE_AND_PAD + data_size,
            0,
            (struct sockaddr *)&g_ctx->addr,
            sizeof(g_ctx->addr)
    );
    return sent != SOCKET_ERROR && sent == HEADERS_SIZE_AND_PAD + data_size;
}


static bool _ss_recv(void) {
    int fromlen = (int)sizeof(g_ctx->addr);
    int recv = recvfrom(
            g_ctx->sock,
            (char *)&g_ctx->transfer,
            MAX_UDP,
            0,
            (struct sockaddr *)&g_ctx->addr,
            &fromlen
    );
    return recv != SOCKET_ERROR && recv == HEADERS_SIZE_AND_PAD + g_ctx->transfer.headers.data_size;
}


union BUF_INFO {
    char bytes[4];
    int size;
};

bool ss_init(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Could not start wsa\n");
        return false;
    }

    //                  [         MAX_UDP          ]
    // [[sock][sockaddr][  headers  ][    data    ][\0]]
    size_t size = offsetof(Context, transfer.headers) + MAX_UDP + 1;
    g_ctx = malloc(size);
    if (!g_ctx) return false;

    char *as_char = (char *)g_ctx;
    as_char[size - 1] = 0;

    g_ctx->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ctx->sock == INVALID_SOCKET) return false;

    unsigned optval;
    int optlen = sizeof(optval);
    int err = getsockopt(g_ctx->sock, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    if (err || optval < MAX_UDP) return false;

    g_ctx->addr = get_server_addr();
    memcpy(g_ctx->transfer.headers.magic, g_transfer_magic, sizeof(g_transfer_magic));

#ifdef COMMON_CLIENT_SIDE
    int flags[] = { SO_SNDTIMEO, SO_RCVTIMEO };
    for (int i = 0; i < 2; ++i) {
        DWORD timeout = SS_TIMEOUT_MS;
        int err = setsockopt(g_ctx->sock, SOL_SOCKET, flags[i], (char *)&timeout, sizeof(timeout));
        assert(!err);

        // MS Windows documentation says that we can't pass these two flags to
        // `getsockopt`. It works here, but I won't assert below
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-getsockopt
        err = getsockopt(g_ctx->sock, SOL_SOCKET, flags[i], (char *)&optval, &optlen);
        if (!err) assert(optval == timeout);
    }
#endif

    return true;
}


void ss_shutdown(void) {
    int err = shutdown(g_ctx->sock, SD_BOTH);
    assert(!err);
    err = closesocket(g_ctx->sock);
    assert(!err);
    err = WSACleanup();
    assert(!err);
    free(g_ctx);
    g_ctx = NULL;
}

#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>


#define TERM_ESC 27

#define term_alt_sc_buf()                     printf("%c[?1049h", TERM_ESC)
#define term_main_sc_buf()                    printf("%c[?1049l", TERM_ESC)
#define term_enter_drawing()                  printf("%c(0",      TERM_ESC)
#define term_exit_drawing()                   printf("%c(B",      TERM_ESC)
#define term_set_cursor_position(x, y)        printf("%c[%d;%dH", TERM_ESC, y, x)
#define term_show_cursor()                    printf("%c[?25h",   TERM_ESC)
#define term_hide_cursor()                    printf("%c[?25l",   TERM_ESC)

#define term_buf_alt_sc_buf(b)                sprintf(b, "%c[?1049h", TERM_ESC)
#define term_buf_main_sc_buf(b)               sprintf(b, "%c[?1049l", TERM_ESC)
#define term_buf_enter_drawing(b)             sprintf(b, "%c(0",      TERM_ESC)
#define term_buf_exit_drawing(b)              sprintf(b, "%c(B",      TERM_ESC)
#define term_buf_set_cursor_position(b, x, y) sprintf(b, "%c[%d;%dH", TERM_ESC, y, x)
#define term_buf_show_cursor(b)               sprintf(b, "%c[?25h",   TERM_ESC)
#define term_buf_hide_cursor(b)               sprintf(b, "%c[?25l",   TERM_ESC)

#define TERM_DRAW_DR  "j"
#define TERM_DRAW_UR  "k"
#define TERM_DRAW_UL  "l"
#define TERM_DRAW_DL  "m"
#define TERM_DRAW_4W  "n"
#define TERM_DRAW_HOR "q"
#define TERM_DRAW_UDR "t"
#define TERM_DRAW_UDL "u"
#define TERM_DRAW_LRU "v"
#define TERM_DRAW_LRD "w"
#define TERM_DRAW_VER "x"

typedef enum {
    SGR_DEFAULT = 0,
    SGR_BOLD,

    SGR_UNDERLINE = 4,

    SGR_NEGATIVE = 7,

    SGR_NO_BOLD = 22,
    SGR_NO_UNDERLINE = 24,

    SGR_POSITIVE = 27,

    SGR_F_BLACK = 30,
    SGR_F_RED,
    SGR_F_GREEN,
    SGR_F_YELLOW,
    SGR_F_BLUE,
    SGR_F_MAGENTA,
    SGR_F_CYAN,
    SGR_F_WHITE,

    // not included bc needs a different parsing
    // SGR_F_EXTENDED,

    SGR_F_DEFAULT = 39,
    SGR_B_BLACK,
    SGR_B_RED,
    SGR_B_GREEN,
    SGR_B_YELLOW,
    SGR_B_BLUE,
    SGR_B_MAGENTA,
    SGR_B_CYAN,
    SGR_B_WHITE,

    // SGR_B_EXTENDED,

    SGR_B_DEFAULT = 49,

    SGR_BF_BLACK = 90,
    SGR_BF_RED,
    SGR_BF_GREEN,
    SGR_BF_YELLOW,
    SGR_BF_BLUE,
    SGR_BF_MAGENTA,
    SGR_BF_CYAN,
    SGR_BF_WHITE,

    SGR_BB_BLACK = 100,
    SGR_BB_RED,
    SGR_BB_GREEN,
    SGR_BB_YELLOW,
    SGR_BB_BLUE,
    SGR_BB_MAGENTA,
    SGR_BB_CYAN,
    SGR_BB_WHITE,
} SetGraphicsRendition;


typedef enum {
    CSI_UP = 'A',
    CSI_DOWN,
    CSI_RIGHT,
    CSI_LEFT,
    CSI_LINE_DOWN,  // resets x pos
    CSI_LINE_UP,
    CSI_X_ABS,

    MOD_ERASE_DISPLAY = 'J',   // values must be 0, 1 or 2
    MOD_ERASE_LINE,            // same
    MOD_INSERT_LINE,
    MOD_DELETE_LINE,
    MOD_DELETE_CHAR = 'P',
    MOD_ERASE_CHAR = 'X',
    MOD_INSERT_CHAR = '@',

    VPP_SCROLL_UP = 'S',
    VPP_SCROLL_DOWN,

    CSI_Y_ABS = 'd'
} CSI_MOD_VPP;


// #define TERM_IMPLEMENTATION
#ifdef TERM_IMPLEMENTATION
int static inline term_sgr(SetGraphicsRendition sgr) {
    return printf("%c[%dm", TERM_ESC, sgr);
}
int static inline term_buf_sgr(char *buf, SetGraphicsRendition sgr) {
    return sprintf(buf, "%c[%dm", TERM_ESC, sgr);
}

int static inline term_csi_mod_vpp(CSI_MOD_VPP code, int16_t value) {
    return printf("%c[%d%c", TERM_ESC, value, code);
}
int static inline term_buf_csi_mod_vpp(char *buf, CSI_MOD_VPP code, int16_t value) {
    return sprintf(buf, "%c[%d%c", TERM_ESC, value, code);
}

int static inline term_sgr_ex_color(bool is_fore, unsigned char r, unsigned char g, unsigned char b) {
    int sgr_code = is_fore ? 38 : 48;
    return printf("%c[%d;2;%d;%d;%dm", TERM_ESC, sgr_code, r, g, b);
}
int static inline term_buf_sgr_ex_color(char *buf, bool is_fore, unsigned char r, unsigned char g, unsigned char b) {
    int sgr_code = is_fore ? 38 : 48;
    return sprintf(buf, "%c[%d;2;%d;%d;%dm", TERM_ESC, sgr_code, r, g, b);
}
#else
#define term_sgr(sgr)                                printf("%c[%dm",  TERM_ESC, sgr)
#define term_buf_sgr(b, sgr)                         sprintf(b, "%c[%dm",  TERM_ESC, sgr)

#define term_csi_mod_vpp(code, value)                printf("%c[%d%c", TERM_ESC, value, code)
#define term_buf_csi_mod_vpp(b, code, value)         sprintf(b, "%c[%d%c", TERM_ESC, value, code)

#define term_sgr_ex_color(is_fore, r, g, b)          printf("%c[%d;2;%d;%d;%dm", TERM_ESC, is_fore ? 38 : 48, r, g, b);
#define term_buf_sgr_ex_color(buf, is_fore, r, g, b) sprintf(buf, "%c[%d;2;%d;%d;%dm", TERM_ESC, is_fore ? 38 : 48, r, g, b);
#endif  // TERM_IMPLEMENTATION

#define term_csi(code, value)        term_csi_mod_vpp(code, value)
#define term_buf_csi(b, code, value) term_buf_csi_mod_vpp(b, code, value)

#define term_mod(code, value)        term_csi_mod_vpp(code, value)
#define term_buf_mod(b, code, value) term_buf_csi_mod_vpp(b, code, value)

#define term_vpp(code, value)        term_csi_mod_vpp(code, value)
#define term_buf_vpp(b, code, value) term_buf_csi_mod_vpp(b, code, value)

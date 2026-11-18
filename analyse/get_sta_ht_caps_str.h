/* get_sta_ht_caps_str harness types (namespace gsh). Own header, kept out of common.h so `make` stays incremental. */
#ifndef GET_STA_HT_CAPS_STR_H
#define GET_STA_HT_CAPS_STR_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace gsh {
#define GSH_GUARD 64          /* bytes before / after ht_cap[] and after the output buffer, poisoned by the runner */
#define GSH_BUF_SZ 32         /* caps_str[32] of the caller (sta_get_inner / sta_tget_params) */
#define GSH_HT_SZ 128        /* em_long_string_t ht_cap */

/* the caller's input array and its neighbours: ht_cap is em_long_string_t[128], a stand-in for the members before / after it */
typedef struct {
    unsigned char before[GSH_GUARD];
    char ht_cap[GSH_HT_SZ];
    unsigned char after[GSH_GUARD];
} sta_ht_t;

class em_crypto_t {
public:
    static std::string base64_encode(const uint8_t *in, size_t len)
    {   static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o; size_t i = 0;
        for (; i + 2 < len; i += 3) { uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
            o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += t[v & 63]; }
        if (len - i == 1) { uint32_t v = in[i] << 16; o += t[v >> 18]; o += t[(v >> 12) & 63]; o += "=="; }
        else if (len - i == 2) { uint32_t v = (in[i] << 16) | (in[i+1] << 8); o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += '='; }
        return o; }
};
class dm_easy_mesh_t {
public:
    static unsigned char *unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out);
};
class dm_easy_mesh_ctrl_t {
public:
    char* get_sta_ht_caps_str(char *ht_cap_hex, char *buf, size_t buf_len);
};

typedef struct {
    const char *test_name;
    int gen;                 /* 0: hex used as is, 1: built from cap / rx / tx (+ extra bytes), 2: NULL input, 3: ht_cap filled with 128 'a' and no NUL */
    const char *hex;
    unsigned int cap, mcs, b15; /* gen 1: HT capabilities info (16 bits), rx MCS set bytes 0..3 (byte i = (mcs >> 8*i) & 0xff), byte 15 of the element (Tx MCS set flags) */
    int extra;               /* gen 1: zero bytes appended after the 16 byte element (0..17) */
    bool upper;              /* gen 1: upper-case hex digits */
    size_t buf_len;          /* length passed to the function (<= GSH_BUF_SZ) */
    const char *expect;      /* gen 0 / 2 / 3: expected output ("" = rejected); gen 1: NULL = computed from cap / mcs / b15 by the reference encoder */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char buf_store[GSH_BUF_SZ + GSH_GUARD];
extern sta_ht_t g_sta;
extern char g_hexbuf[GSH_HT_SZ + 1];
extern char g_expect[32];
extern const char *g_in;
void construct_input(const test_case_t *tc);
const char *invoke(char *hex, char *buf, size_t buf_len);
void teardown(void);
}
void run_all_tests_get_sta_ht_caps_str(void);
#endif

/* get_sta_vht_caps_str harness types (namespace gsv). Own header, kept out of common.h so `make` stays incremental. */
#ifndef GET_STA_VHT_CAPS_STR_H
#define GET_STA_VHT_CAPS_STR_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace gsv {
#define GSV_GUARD 64          /* bytes before / after vht_cap[] and after the output buffer, poisoned by the runner */
#define GSV_BUF_SZ 32         /* caps_str[32] of the caller (sta_get_inner / sta_tget_params) */
#define GSV_VHT_SZ 128        /* em_long_string_t vht_cap */

/* the caller's input array and its neighbours: vht_cap is em_long_string_t[128], a stand-in for the members before / after it */
typedef struct {
    unsigned char before[GSV_GUARD];
    char vht_cap[GSV_VHT_SZ];
    unsigned char after[GSV_GUARD];
} sta_vht_t;

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
    char* get_sta_vht_caps_str(char *vht_cap_hex, char *buf, size_t buf_len);
};

typedef struct {
    const char *test_name;
    int gen;                 /* 0: hex used as is, 1: built from cap / rx / tx (+ extra bytes), 2: NULL input, 3: vht_cap filled with 128 'a' and no NUL */
    const char *hex;
    unsigned int cap, rx, tx;/* gen 1: VHT capabilities info, rx / tx MCS maps */
    int extra;               /* gen 1: zero bytes appended after the 12 byte element (0..5) */
    bool upper;              /* gen 1: upper-case hex digits */
    size_t buf_len;          /* length passed to the function (<= GSV_BUF_SZ) */
    const char *expect;      /* gen 0 / 2 / 3: expected output ("" = rejected); gen 1: NULL = computed from cap / rx / tx by the reference encoder */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char buf_store[GSV_BUF_SZ + GSV_GUARD];
extern sta_vht_t g_sta;
extern char g_hexbuf[GSV_VHT_SZ + 1];
extern char g_expect[32];
extern const char *g_in;
void construct_input(const test_case_t *tc);
const char *invoke(char *hex, char *buf, size_t buf_len);
void teardown(void);
}
void run_all_tests_get_sta_vht_caps_str(void);
#endif

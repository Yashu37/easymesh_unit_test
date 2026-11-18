/* sta_tget_params harness types (namespace stp). Own header, kept out of common.h. */
#ifndef STA_TGET_PARAMS_H
#define STA_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace stp {
#define STP_ROOT_LEFT 16
#define STP_ROOT_SZ 700
#define STP_MAXSTA 4
#define EM_MAX_FRAME_BODY_LEN 512
using ccs::bus_error_t; using ccs::bus_error_success;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];
typedef char em_long_string_t[128];
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct { em_interface_t bssid; } em_bss_info_t;
typedef struct {
    mac_address_t id;
    mac_address_t bssid;
    bool associated;
    em_long_string_t ht_cap, vht_cap;
    unsigned int frame_body_len;
    unsigned char frame_body[EM_MAX_FRAME_BODY_LEN];
    unsigned char rest_of_struct[256];      /* the members that follow frame_body[] in the real struct (runner poisons it) */
    unsigned int last_dl_rate, last_ul_rate, util_rx, util_tx, est_dl_rate, est_ul_rate;
    int rcpi;
    unsigned int last_conn_time, bytes_tx, bytes_rx, pkts_tx, pkts_rx, errors_tx, errors_rx, retrans_count;
} em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } /* stand-in for the real walk over frame_body[0 .. frame_body_len) (dm_sta.cpp decode_sta_capability / find_sta_he_caps) */
    static void decode_sta_capability(dm_sta_t *sta)
    { volatile unsigned char s = 0; for (unsigned int i = 0; i < sta->info.frame_body_len; i++) s = (unsigned char)(s + sta->info.frame_body[i]); (void)s; } };
typedef struct { dm_sta_t *p[STP_MAXSTA]; int n; } sta_map_t;
class dm_easy_mesh_t { public: sta_map_t *m_sta_map; };
void *hash_map_get_first(sta_map_t *m);
void *hash_map_get_next(sta_map_t *m, void *cur);
extern dm_easy_mesh_t *g_dm;

typedef struct {
    bool assoc;
    unsigned char bss;     /* last byte of the STA's BSSID; the BSS handed to the handler is 02:00:00:00:00:01; 0 = entry unused */
    int fb_len;            /* frame_body_len */
    const char *ht;        /* ht_cap text */
    const char *vht;
} sta_spec_t;

extern bus_data_prop_t g_dummy_prop;
void rec(unsigned int idx, const char *name, const char *val);

/* stand-ins for the controller classes (handler body is in sta_tget_params.cpp) */
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

static const char *sta_wifi6_cap_members[] = {
    "HE160", "HE8080", "MCSNSS", "SUBeamformer", "SUBeamformee",
    "MUBeamformer", "Beamformee80orLess", "BeamformeeAbove80", "ULMUMIMO",
    "ULOFDMA", "DLOFDMA", "MaxDLMUMIMO", "MaxULMUMIMO", "MaxDLOFDMA",
    "MaxULOFDMA", "RTS", "MURTS", "MultiBSSID", "MUEDCA", "TWTRequestor",
    "TWTResponder", "SpatialReuse", "AnticipatedChannelUsage",
};

class dm_easy_mesh_ctrl_t {
public:
    char *get_sta_ht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    char *get_sta_vht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    bool sta_wifi6_cap_value(em_sta_info_t *si, const char *param, bool *out)
    { (void)si; for (unsigned i = 0; i < sizeof(sta_wifi6_cap_members) / sizeof(sta_wifi6_cap_members[0]); i++)
        if (!strcmp(param, sta_wifi6_cap_members[i])) { *out = (i % 2 == 0); return true; }
      return false; }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
typedef struct {
    const char *test_name;
    const char *root;      /* "LONG" = 600 characters */
    sta_spec_t sta[STP_MAXSTA];
    int expect_rows;       /* number of "MACAddress" properties, -1 = unchecked */
    const char *has;
    const char *not_has;
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[STP_ROOT_LEFT + STP_ROOT_SZ + 64];
extern char g_rec[];
extern int g_rows;
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root);
void teardown(void);
}
void run_all_tests_sta_tget_params(void);
#endif

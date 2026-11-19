/* sta_get_inner harness types (namespace sgi). Own header, kept out of common.h so `make` stays incremental. */
#ifndef STA_GET_INNER_H
#define STA_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace sgi {
#define SGI_LEFT 16          /* poisoned bytes in front of event_name */
#define SGI_NAME_SZ 300
#define SGI_PAD 64
#define SGI_GUARD 256        /* bytes before / after dm->m_radio[] and dm->m_bss[] (neighbouring members), poisoned by the runner */
#define SGI_VAL_SZ 1024
#define SGI_MAXSTA 6
#ifndef EM_MAX_BANDS
#define EM_MAX_BANDS 3
#endif
#ifndef EM_MAX_BSSS
#define EM_MAX_BSSS (EM_MAX_BANDS * 8)
#endif
#ifndef EM_MAX_FRAME_BODY_LEN
#define EM_MAX_FRAME_BODY_LEN 512
#endif

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;

#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
typedef struct { int unused; } bus_user_data_t;
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_long_string_t[128];
static const unsigned char ZERO_MAC_ADDR[6] = {0, 0, 0, 0, 0, 0};

/* em_radio_info_t cut down to the member sta_get_inner reads (only id.ruid) plus the members after it, which the runner poisons. */
typedef struct { struct { unsigned char ruid[6]; } id; unsigned char rest_of_struct[256]; } em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };

typedef struct { struct { unsigned char mac[6]; } ruid; struct { unsigned char mac[6]; } bssid; unsigned char rest_of_struct[256]; } em_bss_info_t;
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };

typedef struct {
    mac_address_t id;
    mac_address_t bssid;
    bool associated;
    char timestamp[32];
    em_long_string_t ht_cap, vht_cap;
    unsigned int frame_body_len;
    unsigned char frame_body[EM_MAX_FRAME_BODY_LEN];
    unsigned char rest_of_struct[256];      /* the members that follow frame_body[] in the real struct (runner poisons it) */
    unsigned int last_dl_rate, last_ul_rate, util_rx, util_tx, est_dl_rate, est_ul_rate;
    int rcpi;
    unsigned int last_conn_time, bytes_tx, bytes_rx, pkts_tx, pkts_rx, errors_tx, errors_rx, retrans_count;
} em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; }
    /* stand-in for the real walk over frame_body[0 .. frame_body_len) (dm_sta.cpp decode_sta_capability) */
    static void decode_sta_capability(dm_sta_t *sta)
    { volatile unsigned char s = 0; for (unsigned int i = 0; i < sta->info.frame_body_len; i++) s = (unsigned char)(s + sta->info.frame_body[i]); (void)s; } };
typedef struct { dm_sta_t *p[SGI_MAXSTA]; int n; } sta_map_t;

class dm_easy_mesh_t {
public:
    unsigned char before[SGI_GUARD];              /* stands for the members in front of m_radio[] */
    dm_radio_t m_radio[EM_MAX_BANDS];
    unsigned char between[SGI_GUARD];             /* stands for the members between m_radio[] and m_num_bss */
    unsigned int m_num_bss;                       /* raw value, nothing clamps it (develop @ 1ba9529) */
    dm_bss_t m_bss[EM_MAX_BSSS];
    unsigned char after[SGI_GUARD];               /* stands for the members after m_bss[] */
    sta_map_t *m_sta_map;
    em_bss_info_t *get_bss_info(unsigned int index) { return m_bss[index].get_bss_info(); }
    static void macbytes_to_string(const unsigned char *mac, char *s)
    { snprintf(s, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
void *hash_map_get_first(sta_map_t *m);
void *hash_map_get_next(sta_map_t *m, void *cur);
extern dm_easy_mesh_t *g_dm;

extern char g_val[SGI_VAL_SZ];
extern int g_nset;

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

/* stand-ins for the controller classes (handler body is in sta_get_inner.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    dm_sta_t *get_dm_sta(dm_easy_mesh_t *dm, em_bss_info_t *bi, int instance);
    char *get_sta_ht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    char *get_sta_vht_caps_str(char *hex, char *buf, size_t n) { snprintf(buf, n, "%s", hex); return buf; }
    bool sta_wifi6_cap_value(em_sta_info_t *si, const char *param, bool *out)
    { (void)si; for (unsigned i = 0; i < sizeof(sta_wifi6_cap_members) / sizeof(sta_wifi6_cap_members[0]); i++)
        if (!strcmp(param, sta_wifi6_cap_members[i])) { *out = (i % 2 == 0); return true; }
      return false; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    bus_error_t raw_data_set(raw_data_t *p, const unsigned char *mac)
    { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t sta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};

typedef struct {
    const char *test_name;
    const char *event;      /* NULL passes a NULL event_name */
    bool no_pdata;
    int expect_rc;          /* 0 success, 2 invalid_input, 25 invalid_namespace */
    const char *expect_val; /* recorded raw_data_set value, NULL = unchecked */
    int variant;            /* 0 normal model, 1 m_num_bss = 100 (> 24), 2 STA 1 frame_body_len = 513, 3 = 65534, 4 = 512, 5 = 0 */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[SGI_LEFT + SGI_NAME_SZ + SGI_PAD];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_sta_get_inner(void);
#endif

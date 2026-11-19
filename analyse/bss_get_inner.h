/* bss_get_inner harness types (namespace bgi). Own header, kept out of common.h so `make` stays incremental. */
#ifndef BSS_GET_INNER_H
#define BSS_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace bgi {
#define BGI_LEFT 16          /* poisoned bytes in front of event_name */
#define BGI_NAME_SZ 300
#define BGI_PAD 64
#define BGI_GUARD 256        /* bytes before / after dm->m_radio[] and dm->m_bss[] (neighbouring members), poisoned by the runner */
#define BGI_VAL_SZ 1024
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

/* em_radio_info_t cut down to the member bss_get_inner reads (only id.ruid) plus the members after it, which the runner poisons. */
typedef struct { struct { unsigned char ruid[6]; } id; unsigned char rest_of_struct[256]; } em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };

typedef enum { em_haul_type_fronthaul = 0, em_haul_type_backhaul = 1, em_haul_type_iot = 2 } em_haul_type_t;
typedef char ssid_t_[33];
typedef char em_string_t[64];
typedef struct {
    struct { em_haul_type_t haul_type; } id;
    struct { unsigned char mac[6]; } bssid;
    struct { unsigned char mac[6]; } ruid;
    ssid_t_ ssid;
    bool enabled;
    unsigned int last_change;
    em_long_string_t timestamp;
    unsigned int numberofsta;
    unsigned int unicast_bytes_sent, unicast_bytes_rcvd, multicast_bytes_sent, multicast_bytes_rcvd, broadcast_bytes_sent, broadcast_bytes_rcvd;
    em_string_t est_svc_params_be, est_svc_params_bk, est_svc_params_vi, est_svc_params_vo;
    unsigned int byte_counter_units;
    bool profile_1b_sta_allowed, profile_2b_sta_allowed;
    unsigned int assoc_allowed_status;
    bool r1_disallowed, r2_disallowed, multi_bssid, transmitted_bssid;
    unsigned char rest_of_struct[256];      /* members the handler never reads (runner poisons them) */
} em_bss_info_t;
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };

class dm_easy_mesh_t {
public:
    unsigned char before[BGI_GUARD];              /* stands for the members in front of m_radio[] */
    dm_radio_t m_radio[EM_MAX_BANDS];
    unsigned char between[BGI_GUARD];             /* stands for the members between m_radio[] and m_num_bss */
    unsigned int m_num_bss;                       /* raw value, nothing clamps it (develop @ 1ba9529) */
    dm_bss_t m_bss[EM_MAX_BSSS];
    unsigned char after[BGI_GUARD];               /* stands for the members after m_bss[] */
    em_bss_info_t *get_bss_info(unsigned int index) { return m_bss[index].get_bss_info(); }
    static void macbytes_to_string(const unsigned char *mac, char *s)
    { snprintf(s, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
extern dm_easy_mesh_t *g_dm;

extern char g_val[BGI_VAL_SZ];
extern int g_nset;

/* stand-ins for the controller classes (handler body is in bss_get_inner.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    void fill_bss_akms_allowed(dm_easy_mesh_t *dm, em_bss_info_t *bi, bool backhaul, char *buf, size_t buf_len)
    {   (void)dm; buf[0] = '\0'; if (backhaul != (bi->id.haul_type == em_haul_type_backhaul)) return;
        snprintf(buf, buf_len, "%s", backhaul ? "wpa2,sae-b" : "psk,sae"); }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    bus_error_t raw_data_set(raw_data_t *p, const unsigned char *mac)
    { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t bss_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
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
    int variant;            /* 0 normal model, 1 m_num_bss = 100 (> 24) */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[BGI_LEFT + BGI_NAME_SZ + BGI_PAD];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_bss_get_inner(void);
#endif

/* dm_bss_t::encode harness types (namespace dbe). Own header, kept out of common.h so `make` stays incremental. */
#ifndef DM_BSS_ENCODE_H
#define DM_BSS_ENCODE_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <cjson/cJSON.h>
#include "common.h"

namespace dbe {
#define DBE_GUARD 256
#define EM_MAX_AKMS 10
#define WIFI_AP_MAX_VENDOR_IE_LEN 2310
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_short_string_t[64]; typedef char em_long_string_t[128]; typedef char em_string_t[32]; typedef char ssid_t[32];
typedef enum { em_haul_type_fronthaul, em_haul_type_backhaul, em_haul_type_iot, em_haul_type_configurator, em_haul_type_hotspot, em_haul_type_max } em_haul_type_t;
typedef struct { char name[32]; mac_address_t mac; int media; } __attribute__((__packed__)) em_interface_t;
typedef struct { em_long_string_t net_id; mac_address_t dev_mac; mac_address_t ruid; mac_address_t bssid; em_haul_type_t haul_type; } em_bss_id_t;

/* em_bss_info_t from inc/em_base.h (eht_ops replaced by an opaque block, it is not read by encode) */
typedef struct {
    unsigned int vap_index; int vap_mode; em_bss_id_t id; em_interface_t bssid; em_interface_t ruid;
    ssid_t ssid; bool enabled; unsigned int last_change; em_long_string_t timestamp; unsigned int numberofsta; unsigned int channel_util;
    unsigned int unicast_bytes_sent, unicast_bytes_rcvd, multicast_bytes_sent, multicast_bytes_rcvd, broadcast_bytes_sent, broadcast_bytes_rcvd;
    bool inc_esp_ac_be, inc_esp_ac_bk, inc_esp_ac_vo, inc_esp_ac_vi;
    em_string_t est_svc_params_be, est_svc_params_bk, est_svc_params_vi, est_svc_params_vo;
    unsigned int byte_counter_units;
    unsigned char num_fronthaul_akms; em_short_string_t fronthaul_akm[EM_MAX_AKMS];
    unsigned char num_backhaul_akms;  em_short_string_t backhaul_akm[EM_MAX_AKMS];
    bool profile_1b_sta_allowed, profile_2b_sta_allowed; unsigned int assoc_allowed_status;
    bool backhaul_use, fronthaul_use, r1_disallowed, r2_disallowed, multi_bssid, transmitted_bssid;
    unsigned char eht_ops[64]; em_short_string_t mesh_sta_passphrase; unsigned int vlan_id; mac_address_t mld_mac; mac_address_t sta_mac;
    unsigned char vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN]; size_t vendor_elements_len; bool connect_status;
} em_bss_info_t;

class dm_easy_mesh_t { public: static char *macbytes_to_string(unsigned char *m, char *s) { sprintf(s, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return s; } };
namespace util { inline std::string mac_to_string(const unsigned char *m) { char b[24]; sprintf(b, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return b; } }

class dm_bss_t {
public:
    unsigned char before_info[DBE_GUARD];     /* members in front of m_bss_info */
    em_bss_info_t m_bss_info;
    unsigned char after_info[DBE_GUARD];      /* members behind m_bss_info */
    void encode(cJSON *obj, bool summary);
    int init() { memset(&m_bss_info, 0, sizeof(em_bss_info_t)); return 0; }
    em_bss_info_t *get_bss_info() { return &m_bss_info; }
};

typedef struct {
    const char *test_name;
    int variant;
    bool summary;
    const char *expect_haul;     /* "HaulType" string, NULL unchecked */
    const char *expect_ssid;     /* "SSID" string, NULL unchecked */
    int expect_fh, expect_bh;    /* sizes of FronthaulAKMsAllowed / BackhaulAKMsAllowed arrays, -1 unchecked */
    int expect_vendor_len;       /* strlen("ExtraVendorIEs"), -1 unchecked */
    int expect_mld;              /* 1 = MLDAddr present, 0 absent, -1 unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern dm_bss_t *g_bss; extern cJSON *g_obj;
void construct_input(const test_case_t *tc);
void dirty_stack(void);
void invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_dm_bss_encode(void);
#endif

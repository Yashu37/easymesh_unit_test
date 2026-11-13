/* device_get_inner harness types (namespace dgi). Own header, kept out of common.h. */
#ifndef DEVICE_GET_INNER_H
#define DEVICE_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace dgi {
#define DGI_LEFT 16
#define DGI_NAME_SZ 300
#define DGI_PAD 64
#define DGI_GUARD 256

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;

#define MAX_INSTANCE_LEN 32
#define MAX_EM_BUFF_SZ 1024
#define EM_BACKHAUL_DOWNMAC_ADDR 16
#define EM_MAX_STA_PER_STEER_POLICY 16
#define WIFI_80211_VARIANT_AC 0x20
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
typedef unsigned char mac_address_t[6];
typedef char em_string_t[32];
typedef char em_short_string_t[64];
typedef char em_long_string_t[128];
static const unsigned char ZERO_MAC_ADDR[6] = { 0, 0, 0, 0, 0, 0 };
typedef struct { int unused; } bus_user_data_t;
typedef struct { unsigned char dev_mac[6]; } em_device_id_t;
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct {
    bool received; unsigned int boot_id;
    unsigned char client_id_len;     char client_id[64];
    unsigned char client_secret_len; char client_secret[64];
} em_ext_device_info_t;
typedef struct {
    em_device_id_t id;
    em_interface_t intf;
    em_long_string_t multi_ap_cap, manufacturer, serial_number, manufacturer_model;
    em_string_t software_ver, exec_env, dscp_map, ctrl_operation_mode;
    char country_code[4];
    unsigned int coll_interval, max_reporting_rate, ap_metrics_reporting_interval, max_vids, max_pri_rules, max_unsuccessful_assoc_report_rate;
    unsigned int backhaul_phyrate, bstamld_maxlinks, max_nummlds, assoc_sta_reporting_int, tidlink_map;
    bool report_unsuccess_assocs, prioritization_sup, report_ind_scans, traffic_sep_allowed, svc_prio_allowed, dfs_enable, coord_cac_allowed;
    unsigned int sta_steer_state, traffic_sep_cap, easy_conn_cap, test_cap;
    em_interface_t backhaul_mac;
    unsigned int num_backhaul_down_mac;
    em_string_t backhaul_down_mac[EM_BACKHAUL_DOWNMAC_ADDR];
    unsigned char rest_of_struct[256];   /* stands for the fields that follow the array in the real struct (runner poisons it) */
    int backhaul_media_type;
    unsigned int uptime, total_mem, free_mem, cached_mem;
    unsigned char cpu_load, cpu_temp;
    em_ext_device_info_t extended_info;
} em_device_info_t;
typedef struct { unsigned char onboarding_proto, integrity_algo, encryption_algo; } em_ieee_1905_security_cap_t;
typedef enum { em_policy_id_type_none = 0, em_policy_id_type_steering_btm = 1, em_policy_id_type_other = 2 } em_policy_id_type_t;
typedef struct {
    struct { em_policy_id_type_t type; } id;
    unsigned int num_sta;
    mac_address_t sta_mac[EM_MAX_STA_PER_STEER_POLICY];
    unsigned char rest_of_struct[256];   /* the real em_policy_t continues after sta_mac[] (runner poisons it) */
} em_policy_t;
class dm_policy_t { public: em_policy_t m_policy; };
typedef struct { dm_policy_t *p[4]; int n; } policy_map_t;
void *hash_map_get_first(policy_map_t *m);
void *hash_map_get_next(policy_map_t *m, void *cur);

class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_easy_mesh_t {
public:
    bool no_dev; unsigned int nradios; em_ieee_1905_security_cap_t sec; bool has_sec;
    policy_map_t *m_policy_map;
    dm_device_t dev;
    dm_device_t *get_device() { return no_dev ? NULL : &dev; }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() { return has_sec ? &sec : NULL; }
    unsigned int get_num_radios() { return nradios; }
};
extern dm_easy_mesh_t *g_dm;
extern dm_easy_mesh_t *g_bh;   /* backhaul parent device (for BackhaulALID) */

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name */
    bool no_pdata;
    bool no_dm;            /* no device registered */
    bool no_dev;           /* dm->get_device() == NULL */
    bool zero_intf_mac;
    bool no_sec;
    bool bh_zero;          /* backhaul MAC all zero */
    bool no_bh_dev;        /* backhaul MAC set but no such device */
    int n_down;            /* num_backhaul_down_mac */
    int n_down_fill;       /* how many backhaul_down_mac entries hold a MAC string */
    int n_policy;          /* 0 = no policy, 1 = one BTM steering policy */
    int num_sta;           /* its num_sta */
    int ext;               /* 0 not received, 1 received without id/secret, 2 with */
    int expect_rc;         /* 0 success, 2 invalid_input, 25 invalid_namespace */
    const char *expect_val;/* recorded raw_data_set value, NULL = unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[DGI_LEFT + DGI_NAME_SZ + DGI_PAD];
extern int g_rc;
extern int g_nset;
extern char g_val[2048];
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_device_get_inner(void);
#endif

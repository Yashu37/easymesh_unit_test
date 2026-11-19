/* affsta_get_inner harness types (namespace afg). Own header, kept out of common.h so `make` stays incremental. */
#ifndef AFFSTA_GET_INNER_H
#define AFFSTA_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace afg {
#define AFG_LEFT 16          /* poisoned bytes in front of event_name */
#define AFG_NAME_SZ 300
#define AFG_PAD 64
#define AFG_GUARD 256        /* bytes between / around the dm arrays (neighbouring members), poisoned by the runner */
#define AFG_VAL_SZ 128
#define AFG_MAXSTA 4
#ifndef EM_MAX_AP_MLD
#define EM_MAX_AP_MLD 64
#endif
#ifndef EM_MAX_ASSOC_STA_MLD
#define EM_MAX_ASSOC_STA_MLD 64
#endif

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;
static const bus_error_t bus_error_destination_not_found = (bus_error_t)5;   /* value from OneWifi bus_common.h */

#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
typedef struct { int unused; } bus_user_data_t;
typedef unsigned char mac_address_t[6];
typedef unsigned char mac_addr_t[6];
typedef char mac_addr_str_t[18];

typedef struct { mac_address_t bssid; mac_address_t link_addr; } em_affiliated_sta_info_t;
typedef struct {
    mac_address_t mac_addr;
    mac_address_t ap_mld_mac_addr;
    bool str, nstr, emlsr, emlmr;
    unsigned char num_affiliated_sta;                       /* unsigned char: up to 255, the array holds EM_MAX_AP_MLD = 64 */
    em_affiliated_sta_info_t affiliated_sta[EM_MAX_AP_MLD];
    unsigned char rest_of_struct[256];                      /* stands for what follows the array (runner poisons it) */
} em_assoc_sta_mld_info_t;
class dm_assoc_sta_mld_t { public: em_assoc_sta_mld_info_t info; em_assoc_sta_mld_info_t *get_assoc_sta_mld_info() { return &info; } };
typedef struct { mac_address_t mac_addr; unsigned char rest_of_struct[256]; } em_ap_mld_info_t;
class dm_ap_mld_t { public: em_ap_mld_info_t info; em_ap_mld_info_t *get_ap_mld_info() { return &info; } };

typedef struct {
    mac_address_t id;
    bool associated;
    unsigned int bytes_tx, bytes_rx, pkts_tx, pkts_rx, errors_tx;
    int rcpi;
    unsigned int est_dl_rate, est_ul_rate;
} em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };
typedef struct { dm_sta_t *p[AFG_MAXSTA]; int n; } sta_map_t;

class dm_easy_mesh_t {
public:
    unsigned char before[AFG_GUARD];              /* members in front of m_ap_mld[] */
    unsigned int m_num_ap_mld;
    dm_ap_mld_t m_ap_mld[EM_MAX_AP_MLD];
    unsigned char between[AFG_GUARD];             /* members between m_ap_mld[] and m_num_assoc_sta_mld */
    unsigned int m_num_assoc_sta_mld;
    dm_assoc_sta_mld_t m_assoc_sta_mld[EM_MAX_ASSOC_STA_MLD];
    unsigned char after[AFG_GUARD];               /* members after m_assoc_sta_mld[] */
    sta_map_t *m_sta_map;
    unsigned int get_num_ap_mld() { return m_num_ap_mld; }
    dm_ap_mld_t *get_ap_mld(unsigned int index) { return &m_ap_mld[index]; }
    unsigned int get_num_assoc_sta_mld() { return m_num_assoc_sta_mld; }
    static void macbytes_to_string(unsigned char *mac, char *s)
    { snprintf(s, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
void *hash_map_get_first(sta_map_t *m);
void *hash_map_get_next(sta_map_t *m, void *cur);
extern dm_easy_mesh_t *g_dm;

extern char g_val[AFG_VAL_SZ];
extern int g_nset;

/* stand-ins for the controller classes (handler body is in affsta_get_inner.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    dm_ap_mld_t *get_dm_ap_mld(dm_easy_mesh_t *dm, char *instance, bool is_num);
    dm_assoc_sta_mld_t *get_dm_sta_mld(dm_easy_mesh_t *dm, em_ap_mld_info_t *ami, char *instance, bool is_num);
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    bus_error_t raw_data_set(raw_data_t *p, const unsigned char *mac)
    { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t affsta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
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
    int expect_rc;          /* 0 success, 2 invalid_input, 5 destination_not_found, 25 invalid_namespace */
    const char *expect_val; /* recorded raw_data_set value, NULL = unchecked */
    int variant;            /* 0 normal model, 1 STA MLD 1 num_affiliated_sta = 100 (> 64), 2 no STAs in the STA map */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[AFG_LEFT + AFG_NAME_SZ + AFG_PAD];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_affsta_get_inner(void);
#endif

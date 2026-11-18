/* stamld_tget_params harness types (namespace smt). Own header, kept out of common.h so `make` stays incremental. */
#ifndef STAMLD_TGET_PARAMS_H
#define STAMLD_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace smt {
#define SMT_ROOT_LEFT 16
#define SMT_ROOT_SZ 700
#define SMT_MAXSTA 4
#define SMT_GUARD 256
#define SMT_MAXMLD 64        /* EM_MAX_ASSOC_STA_MLD */
#ifndef EM_MAX_ASSOC_STA_MLD
#define EM_MAX_ASSOC_STA_MLD 64
#endif
using ccs::bus_error_t; using ccs::bus_error_success; using ccs::bus_error_invalid_input;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];
typedef unsigned char mac_addr_t[6];

typedef struct { mac_address_t bssid; mac_address_t link_addr; } em_affiliated_sta_info_t;
typedef struct {
    mac_address_t mac_addr;
    mac_address_t ap_mld_mac_addr;
    bool str, nstr, emlsr, emlmr;
    unsigned char num_affiliated_sta;
    em_affiliated_sta_info_t affiliated_sta[64];
} em_assoc_sta_mld_info_t;
typedef struct { mac_address_t mac_addr; unsigned char rest[300]; } em_ap_mld_info_t;
typedef struct {
    mac_address_t id;
    bool associated;
    unsigned char rest_of_struct[256];      /* members the handler never reads (runner poisons them) */
    unsigned int last_conn_time, bytes_tx, bytes_rx, pkts_tx, pkts_rx, errors_tx, errors_rx, retrans_count;
} em_sta_info_t;
class dm_assoc_sta_mld_t { public: em_assoc_sta_mld_info_t info; em_assoc_sta_mld_info_t *get_assoc_sta_mld_info() { return &info; } };
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };
typedef struct { dm_sta_t *p[SMT_MAXSTA]; int n; } sta_map_t;
class dm_easy_mesh_t {
public:
    unsigned char before[SMT_GUARD];             /* members in front of m_assoc_sta_mld[] */
    unsigned int m_num_assoc_sta_mld;            /* raw value, get_num_assoc_sta_mld() does not clamp it (develop @ 1ba9529) */
    dm_assoc_sta_mld_t m_assoc_sta_mld[SMT_MAXMLD];
    unsigned char after[SMT_GUARD];              /* members after m_assoc_sta_mld[] */
    sta_map_t *m_sta_map;
    unsigned int get_num_assoc_sta_mld() { return m_num_assoc_sta_mld; }
};
void *hash_map_get_first(sta_map_t *m);
void *hash_map_get_next(sta_map_t *m, void *cur);
extern dm_easy_mesh_t *g_dm;
extern em_ap_mld_info_t g_ami;
extern bus_data_prop_t g_dummy_prop;
extern char g_rec[65536];
extern int g_rows;
extern char g_aff_path[1024];
extern int g_aff_calls;
void rec(unsigned int idx, const char *name, const char *val);

/* stand-ins for the controller classes (handler body is in stamld_tget_params.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t affsta_tget_params(dm_easy_mesh_t *dm, const char *root, em_assoc_sta_mld_info_t *smi, bus_data_prop_t **property);
    bus_error_t stamld_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};

typedef struct { unsigned char ap_mld; unsigned char mac; int naff; } mld_spec_t;   /* last byte of ap_mld_mac_addr (1 = belongs to the handler's AP MLD), last byte of the STA MLD's own mac (0 = entry unused), affiliated count */
typedef struct { bool assoc; unsigned char id; unsigned int tx; unsigned int rx; } sta_spec_t;     /* id = last byte of the STA's id (0 = entry unused) */

typedef struct {
    const char *test_name;
    const char *root;      /* "LONG" = 600 characters */
    int nmld;              /* m_num_assoc_sta_mld (raw); the first min(nmld, 64) entries are filled from mld[] (then a copy of mld[0], ap_mld 9) */
    mld_spec_t mld[3];
    sta_spec_t sta[SMT_MAXSTA];
    int expect_rows;       /* number of "MLDMACAddress" properties, -1 = unchecked */
    const char *has;
    const char *not_has;
    bool no_dm, no_ami, no_prop;
    int expect_rc;         /* 0 success, 2 invalid_input */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[SMT_ROOT_LEFT + SMT_ROOT_SZ + 64];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root, bool no_dm, bool no_ami, bool no_prop);
void teardown(void);
}
void run_all_tests_stamld_tget_params(void);
#endif

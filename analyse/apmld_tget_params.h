/* apmld_tget_params harness types (namespace apt). Own header, kept out of common.h so `make` stays incremental. */
#ifndef APMLD_TGET_PARAMS_H
#define APMLD_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace apt {
#define APT_ROOT_LEFT 16
#define APT_ROOT_SZ 700
#define APT_GUARD 256
#define APT_MAXMLD 64        /* EM_MAX_AP_MLD */
#ifndef EM_MAX_AP_MLD
#define EM_MAX_AP_MLD 64
#endif
using ccs::bus_error_t; using ccs::bus_error_success; using ccs::bus_error_invalid_input;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];

typedef struct {
    mac_address_t mac_addr;
    bool str, nstr, emlsr, emlmr;
    unsigned char num_affiliated_ap;
    unsigned char rest_of_struct[256];      /* members the handler never reads (runner poisons them) */
} em_ap_mld_info_t;
class dm_ap_mld_t { public: em_ap_mld_info_t info; em_ap_mld_info_t *get_ap_mld_info() { return &info; } };
class dm_easy_mesh_t {
public:
    unsigned char before[APT_GUARD];             /* members in front of m_ap_mld[] */
    unsigned int m_num_ap_mld;                   /* raw value, get_num_ap_mld() does not clamp it (develop @ 1ba9529) */
    dm_ap_mld_t m_ap_mld[APT_MAXMLD];
    unsigned char after[APT_GUARD];              /* members after m_ap_mld[] */
    unsigned int n_stamld;                       /* STA MLDs of the AP MLD (not read by the handler; used for the [spec] case) */
    unsigned int get_num_ap_mld() { return m_num_ap_mld; }
    dm_ap_mld_t *get_ap_mld(unsigned int index) { return &m_ap_mld[index]; }
};
extern dm_easy_mesh_t *g_dm;
extern bus_data_prop_t g_dummy_prop;
extern char g_rec[65536];
extern int g_rows;
extern char g_aff_path[1024];
void rec(unsigned int idx, const char *name, const char *val);

/* stand-ins for the controller classes (handler body is in apmld_tget_params.cpp) */
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
    bus_error_t affap_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property);
    bus_error_t stamld_tget_params(dm_easy_mesh_t *dm, const char *root, em_ap_mld_info_t *ami, bus_data_prop_t **property);
    bus_error_t apmld_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};

typedef struct { unsigned char mac; int naff; } mld_spec_t;   /* last byte of the AP MLD mac (0 = entry unused, copy of mld[0]), affiliated AP count */

typedef struct {
    const char *test_name;
    const char *root;      /* "LONG" = 600 characters */
    int nmld;              /* m_num_ap_mld (raw); the first min(nmld, 64) entries are filled from mld[] (then a copy of mld[0]) */
    mld_spec_t mld[3];
    int n_stamld;          /* dm->n_stamld */
    int expect_rows;       /* number of "MLDMACAddress" properties, -1 = unchecked */
    const char *has;
    const char *not_has;
    bool no_dm, no_prop;
    int expect_rc;         /* 0 success, 2 invalid_input */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[APT_ROOT_LEFT + APT_ROOT_SZ + 64];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root, bool no_dm, bool no_prop);
void teardown(void);
}
void run_all_tests_apmld_tget_params(void);
#endif

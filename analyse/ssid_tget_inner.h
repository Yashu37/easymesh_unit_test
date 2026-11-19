/* ssid_tget_inner harness types (namespace sti). Own header, kept out of common.h so `make` stays incremental. */
#ifndef SSID_TGET_INNER_H
#define SSID_TGET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace sti {
#define STI_LEFT 16          /* poisoned bytes in front of event_name (catches event_name[-1]) */
#define STI_NAME_SZ 300
#define STI_PAD 64
#define STI_GUARD 256        /* bytes before / after dm->m_network_ssid[], poisoned by the runner */
#ifndef MAX_EM_BUFF_SZ
#define MAX_EM_BUFF_SZ 1024
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input;
using ccs::raw_data_t; using ccs::bus_data_prop_t;
static const bus_error_t bus_error_invalid_operation = (bus_error_t)6;
typedef struct { int unused; } bus_user_data_t;

class dm_network_ssid_t { public: em_network_ssid_info_t info; em_network_ssid_info_t *get_network_ssid_info() { return &info; } };
class dm_easy_mesh_t {
public:
    unsigned char before[STI_GUARD];             /* stands for the members in front of m_network_ssid[] */
    dm_network_ssid_t m_network_ssid[EM_MAX_NET_SSIDS];
    unsigned char after[STI_GUARD];              /* stands for the members after m_network_ssid[] */
    unsigned int m_num_net_ssids;                /* raw value, get_num_network_ssid() does not clamp it (develop @ 1ba9529) */
    unsigned int get_num_network_ssid() { return m_num_net_ssids; }
    dm_network_ssid_t *get_network_ssid(unsigned int index) { return &m_network_ssid[index]; }
};
extern dm_easy_mesh_t *g_dm;
extern char g_rec[16384];
extern int g_ids;
extern int g_nset;
extern bus_data_prop_t g_dummy_prop;
void rec(unsigned int idx, const char *name, const char *val);

/* stand-ins for the controller classes (handler body is in ssid_tget_inner.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_t *get_first_dm() { return g_dm; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *dm) { (void)dm; return NULL; }   /* hash_map_get_next(NULL) cannot yield an element */
    void fill_comma_sep(em_short_string_t str[], size_t max, char *buf, size_t buf_sz);
    void fill_haul_type(em_haul_type_t hauls[], size_t max, char *buf);
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t raw_data_set(raw_data_t *p, bus_data_prop_t *prop) { (void)prop; g_nset++; p->data_type = ccs::bus_data_type_string; return bus_error_success; }
    bus_error_t ssid_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name */
    bool no_pdata;
    bool no_dm;            /* no data model is registered */
    int nssid;             /* m_num_net_ssids (raw); the first min(nssid, 5) entries are filled */
    int variant;           /* 0 normal, 1 num_bands 200, 2 num_akms 200 (10 filled), 3 num_hauls 200 (8 filled), 4 haul type 9 in slot 2, 5 empty band 1 (band[0] "") */
    int expect_rc;         /* 0 success, 2 invalid_input, 6 invalid_operation */
    int expect_ids;        /* number of "SSID" properties, -1 = unchecked */
    const char *has;       /* "idx:name=value" line that must appear */
    const char *not_has;   /* must NOT appear */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[STI_LEFT + STI_NAME_SZ + STI_PAD];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_ssid_tget_inner(void);
#endif

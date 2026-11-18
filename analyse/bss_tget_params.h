/* bss_tget_params harness types (namespace btp). Own header, kept out of common.h. */
#ifndef BSS_TGET_PARAMS_H
#define BSS_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace btp {
#define BTP_GUARD 256
#define BTP_ROOT_LEFT 16
#define BTP_ROOT_SZ 700
#define BTP_MAXSPEC 6
#define EM_MAX_BANDS 3
#define EM_MAX_BSSS (EM_MAX_BANDS * 8)
#define MAX_EM_BUFF_SZ 1024
using ccs::bus_error_t; using ccs::bus_error_success;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];
typedef char ssid_t[32];
static const unsigned char ZERO_MAC_ADDR[6] = { 0, 0, 0, 0, 0, 0 };
typedef enum { em_haul_type_fronthaul, em_haul_type_backhaul, em_haul_type_iot, em_haul_type_configurator, em_haul_type_hotspot, em_haul_type_max } em_haul_type_t;
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct { struct { em_haul_type_t haul_type; } id; em_interface_t bssid, ruid; ssid_t ssid; bool enabled; unsigned int numberofsta; unsigned int byte_counter_units; } em_bss_info_t;
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
class dm_easy_mesh_t {
public:
    unsigned char before[BTP_GUARD];     /* members in front of m_bss[] (runner poisons it) */
    unsigned int m_num_bss;
    dm_bss_t m_bss[EM_MAX_BSSS];
    unsigned char after[BTP_GUARD];      /* members after m_bss[] (runner poisons it) */
    unsigned int get_num_bss() { return m_num_bss; }
    dm_bss_t *get_bss(unsigned int index) { return &m_bss[index]; }
};
extern dm_easy_mesh_t *g_dm;

typedef struct {
    unsigned char radio;   /* 1..3: ruid 02:00:00:00:00:radio; 0 = entry unused */
    bool zero_bssid;
    int haul;              /* 0 fronthaul, 1 backhaul */
    bool enabled;
    unsigned int nsta;
} bss_spec_t;

extern bus_data_prop_t g_dummy_prop;
void rec(unsigned int idx, const char *name, const char *val);

/* stand-ins for the controller classes (handler body is in bss_tget_params.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    void fill_bss_akms_allowed(dm_easy_mesh_t *dm, em_bss_info_t *bi, bool backhaul, char *buf, size_t buf_len)
    { (void)dm; buf[0] = '\0'; if (backhaul == (bi->id.haul_type == em_haul_type_backhaul)) snprintf(buf, buf_len, "psk"); }
    void sta_tget_params(dm_easy_mesh_t *dm, const char *path, em_bss_info_t *bi, bus_data_prop_t **prop) { (void)dm; (void)bi; (void)prop; rec(0, "sta_path", path); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const char *v)
    { (void)root; if (!*prop) *prop = &g_dummy_prop; rec(idx, name, v ? v : "(null)"); }
    void property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, const unsigned char *mac)
    { char s[18]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); rec(idx, name, s); }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value || std::is_enum<T>::value>::type
    property_append_tail(bus_data_prop_t **prop, const char *root, unsigned int idx, const char *name, T v)
    { char s[32]; (void)root; if (!*prop) *prop = &g_dummy_prop; snprintf(s, sizeof(s), "%lld", (long long)v); rec(idx, name, s); }
    bus_error_t bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);
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
    int ri_radio;          /* radio whose BSSs are listed */
    bss_spec_t bss[BTP_MAXSPEC];
    int fill_all;          /* >0: fill this many entries (radio 1, valid) instead of the list */
    int n_bss;             /* raw m_num_bss; -1 = number of entries filled */
    int expect_rows;       /* number of "BSSID" properties, -1 = unchecked */
    const char *has;
    const char *not_has;
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[BTP_ROOT_LEFT + BTP_ROOT_SZ + 64];
extern char g_rec[];
extern int g_rows;
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root, int ri_radio);
void teardown(void);
}
void run_all_tests_bss_tget_params(void);
#endif

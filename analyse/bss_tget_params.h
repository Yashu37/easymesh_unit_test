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

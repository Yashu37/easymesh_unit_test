/* sta_tget_params harness types (namespace stp). Own header, kept out of common.h. */
#ifndef STA_TGET_PARAMS_H
#define STA_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace stp {
#define STP_ROOT_LEFT 16
#define STP_ROOT_SZ 700
#define STP_MAXSTA 4
#define EM_MAX_FRAME_BODY_LEN 512
using ccs::bus_error_t; using ccs::bus_error_success;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];
typedef char em_long_string_t[128];
typedef struct { unsigned char mac[6]; } em_interface_t;
typedef struct { em_interface_t bssid; } em_bss_info_t;
typedef struct {
    mac_address_t id;
    mac_address_t bssid;
    bool associated;
    em_long_string_t ht_cap, vht_cap;
    unsigned int frame_body_len;
    unsigned char frame_body[EM_MAX_FRAME_BODY_LEN];
    unsigned char rest_of_struct[256];      /* the members that follow frame_body[] in the real struct (runner poisons it) */
    unsigned int last_dl_rate, last_ul_rate, util_rx, util_tx, est_dl_rate, est_ul_rate;
    int rcpi;
    unsigned int last_conn_time, bytes_tx, bytes_rx, pkts_tx, pkts_rx, errors_tx, errors_rx, retrans_count;
} em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } static void decode_sta_capability(dm_sta_t *sta) { (void)sta; } };
typedef struct { dm_sta_t *p[STP_MAXSTA]; int n; } sta_map_t;
class dm_easy_mesh_t { public: sta_map_t *m_sta_map; };
void *hash_map_get_first(sta_map_t *m);
void *hash_map_get_next(sta_map_t *m, void *cur);
extern dm_easy_mesh_t *g_dm;

typedef struct {
    bool assoc;
    unsigned char bss;     /* last byte of the STA's BSSID; the BSS handed to the handler is 02:00:00:00:00:01; 0 = entry unused */
    int fb_len;            /* frame_body_len */
    const char *ht;        /* ht_cap text */
    const char *vht;
} sta_spec_t;

typedef struct {
    const char *test_name;
    const char *root;      /* "LONG" = 600 characters */
    sta_spec_t sta[STP_MAXSTA];
    int expect_rows;       /* number of "MACAddress" properties, -1 = unchecked */
    const char *has;
    const char *not_has;
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[STP_ROOT_LEFT + STP_ROOT_SZ + 64];
extern char g_rec[];
extern int g_rows;
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root);
void teardown(void);
}
void run_all_tests_sta_tget_params(void);
#endif

/* dm_bss_list_t::sync_db harness types (namespace bsd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef BSS_SYNC_DB_H
#define BSS_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include "common.h"

namespace bsd {
#define BSD_CELL_SZ 4096
#define BSD_GUARD 32
#define BSD_COLS 21
#define BSD_ROWS 3
#define EM_MAX_AKMS 10
#define WIFI_AP_MAX_VENDOR_IE_LEN 2310
#define MIN_MAC_LEN 12
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_string_t[32]; typedef char em_short_string_t[64]; typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef char ssid_t[32]; typedef char em_interface_name_t[32];
typedef int em_haul_type_t; typedef int em_media_type_t;
typedef struct { em_interface_name_t name; mac_address_t mac; em_media_type_t media; } __attribute__((__packed__)) em_interface_t;
typedef struct { em_long_string_t net_id; mac_address_t dev_mac; mac_address_t ruid; mac_address_t bssid; em_haul_type_t haul_type; } em_bss_id_t;
/* em_bss_info_t as in inc/em_base.h (the EHT operations member is replaced by 16 plain bytes) */
typedef struct {
    int vap_mode; em_bss_id_t id; em_interface_t bssid; em_interface_t ruid; ssid_t ssid; bool enabled; unsigned int last_change;
    em_long_string_t timestamp; unsigned int numberofsta; unsigned int channel_util;
    unsigned int unicast_bytes_sent, unicast_bytes_rcvd, multicast_bytes_sent, multicast_bytes_rcvd, broadcast_bytes_sent, broadcast_bytes_rcvd;
    bool inc_esp_ac_be, inc_esp_ac_bk, inc_esp_ac_vo, inc_esp_ac_vi;
    em_string_t est_svc_params_be, est_svc_params_bk, est_svc_params_vi, est_svc_params_vo; unsigned int byte_counter_units;
    unsigned char num_fronthaul_akms; em_short_string_t fronthaul_akm[EM_MAX_AKMS]; unsigned char num_backhaul_akms; em_short_string_t backhaul_akm[EM_MAX_AKMS];
    bool profile_1b_sta_allowed, profile_2b_sta_allowed; unsigned int assoc_allowed_status; bool backhaul_use, fronthaul_use, r1_disallowed, r2_disallowed, multi_bssid, transmitted_bssid;
    unsigned char eht_ops[16]; em_short_string_t mesh_sta_passphrase; unsigned int vlan_id; mac_address_t mld_mac; mac_address_t sta_mac;
    unsigned char vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN]; size_t vendor_elements_len; bool connect_status;
} em_bss_info_t;
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;
class dm_bss_t { public: em_bss_info_t m_bss_info; dm_bss_t(em_bss_info_t *b) { memcpy(&m_bss_info, b, sizeof(m_bss_info)); }
    static int parse_bss_id_from_key(const char *key, em_bss_id_t *id); };
class dm_easy_mesh_t { public: static void string_to_macbytes(char *key, mac_address_t bmac); };

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[BSD_GUARD]; char s[BSD_CELL_SZ]; unsigned char after[BSD_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[BSD_COLS]; } row_t;
extern row_t g_rows[BSD_ROWS]; extern int g_nrows;
class db_client_t {
public:
    int pos;
    bool next_result(void *ctx) { (void)ctx; if (pos >= g_nrows) return false; pos++; return true; }
    char *get_string(void *ctx, char *str, unsigned int col)                     /* like the real one: copies strlen + 1 bytes, no size */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; snprintf(str, strlen(c->s) + 1, "%s", c->s); return str; }
    char *get_string(void *ctx, char *str, unsigned int col, size_t size)         /* bounded overload added by fix 1 */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; size_t n = strlen(c->s) + 1; snprintf(str, n < size ? n : size, "%s", c->s); return str; }
    int get_number(void *ctx, unsigned int col) { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; return c->kind == 2 ? c->num : 0; }
};
class db_easy_mesh_t { public: int get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[]); };
class dm_bss_list_t : public db_easy_mesh_t { public:
    void update_list(const dm_bss_t &b, dm_orch_type_t op) { (void)op; g_updates.push_back(b.m_bss_info); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_bss_info_t> g_updates; };

/* "=" default, "@N" N list entries, "#N" N characters 'x', NULL = SQL NULL */
typedef struct {
    const char *test_name;
    const char *id, *bssid, *ruid, *ssid, *fh, *bh;
    int nrows;
    int row2_variant;       /* 0 same as row 0, 1 BSSID / RUID NULL */
    int expect_updates;
    int expect_haul;        /* update 0 id.haul_type, -1 unchecked */
    const char *expect_bssid; /* update 0 bssid, NULL unchecked */
    const char *expect_ssid;  /* update 0 ssid, NULL unchecked */
    int expect_nfh, expect_nbh;   /* -1 unchecked */
    int expect_ts_intact;   /* 1: update 0 timestamp must still be empty */
    int expect_row2_bssid_zero; /* 1: update 1 bssid must be all zero */
    bool crash;
} test_case_t;
extern test_case_t suite[];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_bss_sync_db(void);
#endif

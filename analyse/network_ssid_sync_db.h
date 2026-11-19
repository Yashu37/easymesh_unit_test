/* dm_network_ssid_list_t::sync_db harness types (namespace nss). Own header, kept out of common.h so `make` stays incremental. */
#ifndef NETWORK_SSID_SYNC_DB_H
#define NETWORK_SSID_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include "common.h"

namespace nss {
#define NSS_CELL_SZ 4096
#define NSS_GUARD 32
#define NSS_COLS 13
#define NSS_ROWS 3
#define EM_MAX_BANDS 3
#define EM_MAX_AKMS 10
#define EM_MAX_HAUL_TYPES 8
#define MIN_MAC_LEN 12
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_short_string_t[64]; typedef char em_string_t[32]; typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef char ssid_t[32];
typedef enum { em_haul_type_fronthaul, em_haul_type_backhaul, em_haul_type_iot, em_haul_type_configurator, em_haul_type_hotspot, em_haul_type_max } em_haul_type_t;
/* em_network_ssid_info_t as in inc/em_base.h */
typedef struct {
    em_long_string_t id; ssid_t ssid; em_long_string_t pass_phrase; unsigned char num_bands; em_short_string_t band[EM_MAX_BANDS];
    bool enable; unsigned char num_akms; em_short_string_t akm[EM_MAX_AKMS]; em_string_t suite_select; bool advertisement; em_string_t mfp;
    mac_address_t mobility_domain; unsigned char num_hauls; em_haul_type_t haul_type[EM_MAX_HAUL_TYPES]; em_string_t auth_type; unsigned short vlan_id;
} em_network_ssid_info_t;
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;
class dm_network_ssid_t { public: em_network_ssid_info_t m_network_ssid_info;
    dm_network_ssid_t(em_network_ssid_info_t *n) { memcpy(&m_network_ssid_info, n, sizeof(m_network_ssid_info)); }
    static em_haul_type_t haul_type_from_string(em_string_t str); };
class dm_easy_mesh_t { public: static void string_to_macbytes(char *key, mac_address_t bmac); };

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[NSS_GUARD]; char s[NSS_CELL_SZ]; unsigned char after[NSS_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[NSS_COLS]; } row_t;
extern row_t g_rows[NSS_ROWS]; extern int g_nrows;
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
class dm_network_ssid_list_t : public db_easy_mesh_t { public:
    void update_list(const dm_network_ssid_t &n, dm_orch_type_t op) { (void)op; g_updates.push_back(n.m_network_ssid_info); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_network_ssid_info_t> g_updates; };

/* a list column shorthand: "@N" = N entries (band b0,b1.. / akm a0,a1.. / haul Fronthaul,Fronthaul..), "#N" = N characters 'x', NULL = SQL NULL, "=" = default */
typedef struct {
    const char *test_name;
    const char *id, *ssid, *pass, *bands, *akms, *suite, *mfp, *mac, *hauls, *auth;
    int nrows;
    int expect_updates, expect_nb, expect_na, expect_nh;   /* -1 unchecked */
    int expect_h0, expect_h1;                               /* em_haul_type_t, -1 unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_network_ssid_sync_db(void);
#endif

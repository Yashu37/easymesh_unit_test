/* dm_policy_list_t::sync_db harness types (namespace spl). Own header, kept out of common.h so `make` stays incremental. */
#ifndef POLICY_SYNC_DB_H
#define POLICY_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include "common.h"

namespace spl {
#define SPL_CELL_SZ 2048
#define SPL_GUARD 32
#define SPL_COLS 18
#define SPL_ROWS 3
#define EM_MAX_STA_PER_STEER_POLICY 16
typedef unsigned char mac_address_t[6];
typedef char em_short_string_t[64]; typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef int em_policy_id_type_t; typedef int em_steering_policy_type_t;
typedef struct { em_long_string_t net_id; mac_address_t dev_mac; mac_address_t radio_mac; em_policy_id_type_t type; } em_policy_id_t;
typedef struct { unsigned short primary_vid; unsigned char default_pcp; } em_8021q_settings_policy_t;
/* em_policy_t cut down to the members sync_db writes; rest_of_struct stands for the remaining (large) members */
typedef struct {
    em_policy_id_t id; unsigned int num_sta; mac_address_t sta_mac[EM_MAX_STA_PER_STEER_POLICY];
    em_steering_policy_type_t policy; unsigned short util_threshold, rcpi_threshold, interval, rcpi_hysteresis;
    bool sta_traffic_stats, sta_link_metric, sta_status; em_long_string_t managed_sta_marker; bool independent_scan_report;
    bool profile_1_sta_disallowed, profile_2_sta_disallowed; em_8021q_settings_policy_t def_8021q_settings;
    unsigned char rest_of_struct[256];
} em_policy_t;
class dm_policy_t { public: em_policy_t m_policy; dm_policy_t(em_policy_t *p) { memcpy(&m_policy, p, sizeof(m_policy)); }
    static int parse_dev_radio_mac_from_key(const char *key, em_policy_id_t *id); };
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;

class dm_easy_mesh_t { public: static void string_to_macbytes(char *key, mac_address_t bmac); };

/* scripted DB: SPL_ROWS rows of SPL_COLS cells; every string cell sits between poisoned guards */
typedef struct { unsigned char before[SPL_GUARD]; char s[SPL_CELL_SZ]; unsigned char after[SPL_GUARD]; int kind; int num; } cell_t;   /* kind 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[SPL_COLS]; } row_t;
extern row_t g_rows[SPL_ROWS]; extern int g_nrows;
class db_client_t {
public:
    int pos;
    bool next_result(void *ctx) { (void)ctx; if (pos >= g_nrows) return false; pos++; return true; }
    char *get_string(void *ctx, char *str, unsigned int col)                       /* same as the real one: copies strlen + 1 bytes, no size */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; snprintf(str, strlen(c->s) + 1, "%s", c->s); return str; }
    char *get_string(void *ctx, char *str, unsigned int col, size_t size)           /* the bounded overload added by fix 1 */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; size_t n = strlen(c->s) + 1; snprintf(str, n < size ? n : size, "%s", c->s); return str; }
    int get_number(void *ctx, unsigned int col) { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; return c->kind == 2 ? c->num : 0; }
};
class db_easy_mesh_t { public: int get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[]); };
class dm_policy_list_t : public db_easy_mesh_t {
public:
    void update_list(const dm_policy_t &p, dm_orch_type_t op) { (void)op; g_updates.push_back(p.m_policy); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_policy_t> g_updates;
};

typedef struct {
    const char *test_name;
    const char *sta_list;     /* row 0 column 4 STAList (NULL = SQL NULL) */
    int nrows;                /* rows returned by the DB */
    int row2_variant;         /* 0 same as row 0, 1 STAList NULL, 2 key NULL */
    int expect_updates;
    int expect_num_sta;       /* update 0, -1 unchecked */
    const char *expect_mac0;  /* first STA MAC of update 0, NULL unchecked */
    int expect_interval;      /* update 0 interval, -1 unchecked */
    int expect_num_sta2;      /* update 1, -1 unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern int g_nupd;
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_policy_sync_db(void);
#endif

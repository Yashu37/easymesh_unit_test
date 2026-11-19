/* dm_network_list_t::sync_db harness types (namespace nsd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef NETWORK_SYNC_DB_H
#define NETWORK_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include "common.h"

namespace nsd {
#define NSD_CELL_SZ 4096
#define NSD_GUARD 32
#define NSD_COLS 4
#define NSD_ROWS 3
#define EM_DATE_TIME_BUFF_SZ 64
#define MIN_MAC_LEN 12
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_string_t[32]; typedef char em_long_string_t[128]; typedef char em_interface_name_t[32];
typedef int em_media_type_t;
typedef struct { em_interface_name_t name; mac_address_t mac; em_media_type_t media; } __attribute__((__packed__)) em_interface_t;
/* em_network_info_t as in inc/em_base.h */
typedef struct {
    em_long_string_t id; unsigned short num_of_devices; em_long_string_t timestamp; em_interface_t ctrl_id;
    unsigned char num_mscs_disallowed_sta; em_string_t mscs_disallowed_sta[10];
    unsigned char num_scs_disallowed_sta; em_string_t scs_disallowed_sta[10];
    em_interface_t colocated_agent_id; em_media_type_t media;
} em_network_info_t;
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;
class dm_network_t { public: em_network_info_t m_net_info; dm_network_t(em_network_info_t *n) { memcpy(&m_net_info, n, sizeof(m_net_info)); } };

namespace util { char *get_date_time_rfc3399(char *buff, unsigned int len); }
class dm_easy_mesh_t { public: static void string_to_macbytes(char *key, mac_address_t bmac); };

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[NSD_GUARD]; char s[NSD_CELL_SZ]; unsigned char after[NSD_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[NSD_COLS]; } row_t;
extern row_t g_rows[NSD_ROWS]; extern int g_nrows;
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
class dm_network_list_t { public:
    void update_list(const dm_network_t &n, dm_orch_type_t op) { (void)op; g_updates.push_back(n.m_net_info); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_network_info_t> g_updates; };

typedef struct {
    const char *test_name;
    const char *id;         /* column 1: "#N" = N characters 'I' (NULL = SQL NULL) */
    const char *ctrl_mac;   /* column 2: "#N" = N characters 'a' */
    const char *colo_mac;   /* column 3 */
    int nrows;
    int row2_variant;       /* 0 same as row 0, 1 all string columns NULL */
    int expect_updates;
    const char *expect_ctrl;    /* "aa:bb:.." of update 0 ctrl_id.mac, NULL unchecked */
    const char *expect_colo;    /* update 1 colocated mac when set, else update 0 */
    int expect_ts_intact;   /* 1: update 0 timestamp must still be the date string (starts with a digit, 20 chars) */
    int expect_row2_ctrl_zero; /* 1: update 1 ctrl mac must be all zero (NULL column must not keep the previous row) */
    bool crash;
} test_case_t;
extern test_case_t suite[];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_network_sync_db(void);
#endif

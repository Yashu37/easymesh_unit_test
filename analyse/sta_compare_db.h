/* dm_sta_list_t::compare_db harness types (namespace scd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef STA_COMPARE_DB_H
#define STA_COMPARE_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace scd {
#define SCD_CELL_SZ 4096
#define SCD_GUARD 32
#define SCD_COLS 22
#define SCD_ROWS 3
#define EM_MAX_FRAME_BODY_LEN 512
#define MIN_MAC_LEN 12
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char db_query_t[2048];
/* em_sta_info_t cut down to the members compare_db fills and memcmp()s; rest_of_struct stands for the remaining members (same in both) */
typedef struct {
    mac_address_t id, bssid, radiomac; bool associated;
    unsigned int last_ul_rate, last_dl_rate, est_ul_rate, est_dl_rate, last_conn_time, retrans_count; signed int signal_strength;
    unsigned char rcpi; unsigned int util_tx, util_rx, pkts_tx, pkts_rx, bytes_tx, bytes_rx, errors_tx, errors_rx;
    unsigned int frame_body_len; unsigned char frame_body[EM_MAX_FRAME_BODY_LEN]; unsigned char rest_of_struct[64];
} em_sta_info_t;
class dm_sta_t { public: em_sta_info_t m_sta_info; };

class dm_easy_mesh_t { public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
    static unsigned char *unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out);
};

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[SCD_GUARD]; char s[SCD_CELL_SZ]; unsigned char after[SCD_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[SCD_COLS]; } row_t;
extern row_t g_rows[SCD_ROWS]; extern int g_nrows;
class db_client_t {
public:
    int pos;
    void *execute(const char *q) { (void)q; pos = 0; return (void *)this; }
    bool next_result(void *ctx) { (void)ctx; if (pos >= g_nrows) return false; pos++; return true; }
    void free_result(void *ctx) { (void)ctx; }
    char *get_string(void *ctx, char *str, unsigned int col)                     /* like the real one: copies strlen + 1 bytes, no size */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; snprintf(str, strlen(c->s) + 1, "%s", c->s); return str; }
    char *get_string(void *ctx, char *str, unsigned int col, size_t size)         /* bounded overload added by fix 1 */
    { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; if (c->kind != 1) return NULL; size_t n = strlen(c->s) + 1; snprintf(str, n < size ? n : size, "%s", c->s); return str; }
    int get_number(void *ctx, unsigned int col) { (void)ctx; cell_t *c = &g_rows[pos - 1].c[col - 1]; return c->kind == 2 ? c->num : 0; }
};
class dm_sta_list_t { public: char m_table_name[64]; dm_sta_list_t() { snprintf(m_table_name, sizeof(m_table_name), "StaList"); }
    bool compare_db(db_client_t &db_client, const dm_sta_t &sta); };

typedef struct {
    const char *test_name;
    const char *mac;        /* column 1 (NULL = SQL NULL) */
    const char *fb;         /* column 22 frame body hex: "#N" = N characters '1', NULL = SQL NULL, else literal */
    int nrows;
    bool sta_matches;       /* the station given to compare_db equals the row */
    int pkts_tx;            /* value of column 15 (and of the station's pkts_tx) */
    int variant;            /* 0 normal, 1 dirty stack with 'A' before the call */
    bool expect_ret;
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern dm_sta_t g_sta;
void construct_input(const test_case_t *tc);
bool invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_sta_compare_db(void);
#endif

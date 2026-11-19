/* dm_sta_list_t::sync_db harness types (namespace ssd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef STA_SYNC_DB_H
#define STA_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "common.h"

namespace ssd {
#define SSD_CELL_SZ 4096
#define SSD_GUARD 32
#define SSD_COLS 22
#define SSD_ROWS 3
#define EM_MAX_FRAME_BODY_LEN 512
#define MIN_MAC_LEN 12
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
/* em_sta_info_t cut down to the members sync_db fills; rest_of_struct stands for the remaining members */
typedef struct {
    mac_address_t id, bssid, radiomac; bool associated;
    unsigned int last_ul_rate, last_dl_rate, est_ul_rate, est_dl_rate, last_conn_time, retrans_count; signed int signal_strength;
    unsigned char rcpi; unsigned int util_tx, util_rx, pkts_tx, pkts_rx, bytes_tx, bytes_rx, errors_tx, errors_rx;
    unsigned int frame_body_len; unsigned char frame_body[EM_MAX_FRAME_BODY_LEN]; unsigned char rest_of_struct[64];
} em_sta_info_t;
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;
class dm_sta_t { public: em_sta_info_t m_sta_info; dm_sta_t(em_sta_info_t *s) { memcpy(&m_sta_info, s, sizeof(m_sta_info)); } };
class dm_easy_mesh_t { public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
    static unsigned char *unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out); };

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[SSD_GUARD]; char s[SSD_CELL_SZ]; unsigned char after[SSD_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[SSD_COLS]; } row_t;
extern row_t g_rows[SSD_ROWS]; extern int g_nrows;
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
class dm_sta_list_t { public:
    void update_list(const dm_sta_t &s, dm_orch_type_t op) { (void)op; g_updates.push_back(s.m_sta_info); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_sta_info_t> g_updates; };

typedef struct {
    const char *test_name;
    const char *mac1, *mac2, *mac3;   /* columns 1-3 ("#N" = N characters 'a', NULL = SQL NULL) */
    const char *fb;                   /* column 22 frame body hex: "#N" = N characters '1', NULL = SQL NULL */
    int nrows;
    int row2_variant;                 /* 0 same as row 0, 1 MAC columns NULL, 2 frame body NULL */
    int expect_updates;
    const char *expect_id;            /* update 0 station MAC, NULL unchecked */
    int expect_b0;                    /* update 0 frame_body[0], -1 unchecked */
    int expect_row2_id_zero;          /* 1: update 1 station MAC must be all zero */
    int expect_row2_b0;               /* update 1 frame_body[0], -1 unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_sta_sync_db(void);
#endif

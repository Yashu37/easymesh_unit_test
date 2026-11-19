/* dm_op_class_list_t::sync_db harness types (namespace ocs). Own header, kept out of common.h so `make` stays incremental. */
#ifndef OPCLASS_SYNC_DB_H
#define OPCLASS_SYNC_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include "common.h"

namespace ocs {
#define OCS_CELL_SZ 4096
#define OCS_GUARD 32
#define OCS_COLS 11
#define OCS_ROWS 3
#define EM_MAX_CHANNELS_IN_LIST 64
#define EM_CH_PREF_ENTRY_VALID 0x01
#define MIN_MAC_LEN 12
#define em_printfout(...) do { } while (0)
typedef unsigned char mac_address_t[6];
typedef char em_short_string_t[64]; typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef enum { em_op_class_type_none, em_op_class_type_current, em_op_class_type_capability, em_op_class_type_cac_available, em_op_class_type_cac_non_occ,
    em_op_class_type_cac_active, em_op_class_type_preference, em_op_class_type_anticipated, em_op_class_type_scan_param, em_op_class_type_selection } em_op_class_type_t;
typedef struct { mac_address_t ruid; em_op_class_type_t type; unsigned int op_class; } em_op_class_id_t;
/* em_op_class_info_t as in inc/em_base.h */
typedef struct {
    em_op_class_id_t id; unsigned int op_class; unsigned int channel; int tx_power; int max_tx_power;
    unsigned int num_channels; unsigned int channels[EM_MAX_CHANNELS_IN_LIST]; unsigned char channel_pref[EM_MAX_CHANNELS_IN_LIST];
    bool pref_valid; unsigned short mins_since_cac_comp; unsigned short sec_remain_non_occ_dur; unsigned int countdown_cac_comp;
} em_op_class_info_t;
typedef enum { dm_orch_type_db_insert = 1 } dm_orch_type_t;
class dm_op_class_t { public: em_op_class_info_t m_op_class_info;
    dm_op_class_t(em_op_class_info_t *o) { memcpy(&m_op_class_info, o, sizeof(m_op_class_info)); }
    static int parse_op_class_id_from_key(const char *key, em_op_class_id_t *id); };
class dm_easy_mesh_t { public: static void string_to_macbytes(char *key, mac_address_t bmac); };

/* scripted DB: every string cell sits between poisoned guards */
typedef struct { unsigned char before[OCS_GUARD]; char s[OCS_CELL_SZ]; unsigned char after[OCS_GUARD]; int kind; int num; } cell_t;   /* 0 NULL, 1 string, 2 number */
typedef struct { cell_t c[OCS_COLS]; } row_t;
extern row_t g_rows[OCS_ROWS]; extern int g_nrows;
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
class dm_op_class_list_t : public db_easy_mesh_t { public:
    void update_list(const dm_op_class_t &o, dm_orch_type_t op) { (void)op; g_updates.push_back(o.m_op_class_info); }
    int sync_db(db_client_t &db_client, void *ctx);
    static std::vector<em_op_class_info_t> g_updates; };

/* list shorthand: "@N" = channels 1..N (preference list: 10 each), "#N" = N characters 'x', NULL = SQL NULL, "=" = default */
typedef struct {
    const char *test_name;
    const char *id, *chans, *prefs;
    int type;               /* id type in the key (1 current, 6 preference, 7 anticipated ...) */
    int channel;            /* column 3 value */
    int nrows;
    int row2_chans_null;    /* second row has a NULL channel column */
    int expect_updates, expect_nch, expect_pref0;           /* -1 unchecked */
    int expect_chan0, expect_chan_last;                     /* -1 unchecked */
    int expect_channel;
    int expect_row2_nch;    /* -1 unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_opclass_sync_db(void);
#endif

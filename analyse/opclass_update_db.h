/* dm_op_class_list_t::update_db harness types (namespace oud). Own header, kept out of common.h so `make` stays incremental. */
#ifndef OPCLASS_UPDATE_DB_H
#define OPCLASS_UPDATE_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace oud {
#define EM_MAX_CHANNELS_IN_LIST 64
#define EM_CH_PREF_ENTRY_VALID 0x01
#define OUD_GUARD 128
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef enum { em_op_class_type_none, em_op_class_type_current, em_op_class_type_capability, em_op_class_type_cac_available, em_op_class_type_cac_non_occ,
    em_op_class_type_cac_active, em_op_class_type_preference, em_op_class_type_anticipated, em_op_class_type_scan_param, em_op_class_type_selection } em_op_class_type_t;
typedef struct { mac_address_t ruid; em_op_class_type_t type; unsigned int op_class; } em_op_class_id_t;
/* em_op_class_info_t as in inc/em_base.h, with a guard behind channels[] and channel_pref[] (stand for the members that follow them, poisoned by the runner) */
typedef struct {
    em_op_class_id_t id; unsigned int op_class; unsigned int channel; int tx_power; int max_tx_power;
    unsigned int num_channels; unsigned int channels[EM_MAX_CHANNELS_IN_LIST]; unsigned char after_channels[OUD_GUARD];
    unsigned char channel_pref[EM_MAX_CHANNELS_IN_LIST]; unsigned char after_pref[OUD_GUARD];
    bool pref_valid; unsigned short mins_since_cac_comp; unsigned short sec_remain_non_occ_dur; unsigned int countdown_cac_comp;
} em_op_class_info_t;
typedef struct { unsigned char before[OUD_GUARD]; em_op_class_info_t info; unsigned char after[OUD_GUARD]; } info_box_t;
typedef enum { dm_orch_type_none = 0, dm_orch_type_db_insert = 1, dm_orch_type_db_update = 2, dm_orch_type_db_delete = 3 } dm_orch_type_t;

class dm_easy_mesh_t { public: static char *macbytes_to_string(mac_address_t mac, char *string); };
class db_client_t { public: int unused; };
extern char g_id[512]; extern char g_channels[512]; extern char g_pref[512]; extern int g_calls;
class dm_op_class_list_t { public:
    int insert_row(db_client_t &db, ...);
    int update_row(db_client_t &db, ...);
    int delete_row(db_client_t &db, ...);
    int update_db(db_client_t &db_client, dm_orch_type_t op, void *data); };

typedef struct {
    const char *test_name;
    int op;
    int type;               /* id type */
    unsigned int num_channels;
    int fill;               /* 0 channels 36,40,44..., 1 channels 100,101,..., 2 channel[0] = 12345678 */
    bool null_data;
    int expect_ret, expect_calls;
    int expect_entries;     /* entries in the channel list, -1 unchecked */
    const char *expect_first; /* first entry of the channel list, NULL unchecked */
    const char *expect_last;  /* last entry of the channel list, NULL unchecked */
    const char *expect_pref;  /* whole preference string, NULL unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern info_box_t *g_box;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_opclass_update_db(void);
#endif

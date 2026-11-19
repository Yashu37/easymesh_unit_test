/* dm_policy_list_t::update_db harness types (namespace pud). Own header, kept out of common.h so `make` stays incremental. */
#ifndef POLICY_UPDATE_DB_H
#define POLICY_UPDATE_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace pud {
#define EM_MAX_STA_PER_STEER_POLICY 16
#define PUD_GUARD 128
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
typedef char em_long_string_t[128]; typedef char em_2xlong_string_t[256];
typedef int em_policy_id_type_t; typedef int em_steering_policy_type_t;
typedef struct { em_long_string_t net_id; mac_address_t dev_mac; mac_address_t radio_mac; em_policy_id_type_t type; } em_policy_id_t;
typedef struct { unsigned short primary_vid; unsigned char default_pcp; } em_8021q_settings_policy_t;
/* em_policy_t cut down to the members update_db reads; after_sta_mac stands for the members that follow sta_mac[] in the real struct (poisoned by the runner) */
typedef struct {
    em_policy_id_t id; unsigned int num_sta; mac_address_t sta_mac[EM_MAX_STA_PER_STEER_POLICY];
    unsigned char after_sta_mac[PUD_GUARD];
    em_steering_policy_type_t policy; unsigned short util_threshold, rcpi_threshold, interval, rcpi_hysteresis;
    bool sta_traffic_stats, sta_link_metric, sta_status; em_long_string_t managed_sta_marker; bool independent_scan_report;
    bool profile_1_sta_disallowed, profile_2_sta_disallowed; em_8021q_settings_policy_t def_8021q_settings;
} em_policy_t;
typedef struct { unsigned char before[PUD_GUARD]; em_policy_t p; unsigned char after[PUD_GUARD]; } policy_box_t;
typedef enum { dm_orch_type_none = 0, dm_orch_type_db_insert = 1, dm_orch_type_db_update = 2, dm_orch_type_db_delete = 3 } dm_orch_type_t;

class dm_easy_mesh_t { public: static char *macbytes_to_string(mac_address_t mac, char *string); };
class db_client_t { public: int unused; };

/* the row functions only record what update_db hands them (key and STA list) */
extern char g_key[512]; extern char g_list[2048]; extern int g_calls;
class dm_policy_list_t {
public:
    int insert_row(db_client_t &db, ...);
    int update_row(db_client_t &db, ...);
    int delete_row(db_client_t &db, ...);
    int update_db(db_client_t &db_client, dm_orch_type_t op, void *data);
};

typedef struct {
    const char *test_name;
    int op;                 /* dm_orch_type_t */
    unsigned int num_sta;
    bool null_data;
    const char *net_id;
    int expect_ret;
    int expect_calls;       /* row function calls (0 or 1) */
    int expect_entries;     /* STA entries in the list handed to the DB, -1 unchecked */
    const char *expect_key; /* NULL unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern policy_box_t *g_box;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_policy_update_db(void);
#endif

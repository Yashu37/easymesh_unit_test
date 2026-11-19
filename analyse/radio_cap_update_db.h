/* dm_radio_cap_list_t::update_db harness types (namespace rcu). Own header, kept out of common.h so `make` stays incremental. */
#ifndef RADIO_CAP_UPDATE_DB_H
#define RADIO_CAP_UPDATE_DB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace rcu {
#define RCU_GUARD 128
#define EM_MAX_FREQ_RECORDS_PER_RADIO 8
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];
/* em_wifi7_agent_cap_t exactly as in inc/em_base.h (488 bytes) */
typedef struct { mac_address_t ruid; unsigned char reserved : 3; unsigned char freq_sep : 5; } __attribute__((__packed__)) em_wifi7_freq_record_tlv_t;
typedef struct { unsigned char num_records; em_wifi7_freq_record_tlv_t records[EM_MAX_FREQ_RECORDS_PER_RADIO]; } __attribute__((__packed__)) em_wifi7_freq_records_t;
typedef struct {
    mac_address_t ruid; unsigned char reserved3[24];
    unsigned char reserved4 : 4; unsigned char ap_emlmr_support : 1; unsigned char ap_emlsr_support : 1; unsigned char ap_nstr_support : 1; unsigned char ap_str_support : 1;
    unsigned char reserved5 : 4; unsigned char bsta_emlmr_support : 1; unsigned char bsta_emlsr_support : 1; unsigned char bsta_nstr_support : 1; unsigned char bsta_str_support : 1;
} __attribute__((__packed__)) em_wifi7_mlo_cap_support_tlv_t;
typedef struct {
    em_wifi7_freq_records_t ap_str, ap_nstr, ap_emlsr, ap_emlmr, bsta_str, bsta_nstr, bsta_emlsr, bsta_emlmr;
} __attribute__((__packed__)) em_wifi7_mlo_cap_records_t;
typedef struct { em_wifi7_mlo_cap_support_tlv_t mlo_cap_support; em_wifi7_mlo_cap_records_t mlo_cap_records; } __attribute__((__packed__)) em_wifi7_agent_cap_t;
typedef struct { unsigned char b[8]; } em_ap_ht_cap_t; typedef struct { unsigned char b[8]; } em_ap_vht_cap_t; typedef struct { unsigned char b[8]; } em_ap_he_cap_t;
/* em_radio_cap_info_t cut down to the members update_db reads */
typedef struct { mac_address_t mac; } em_intf_t;
typedef struct { em_intf_t ruid; em_ap_ht_cap_t ht_cap; em_ap_vht_cap_t vht_cap; em_ap_he_cap_t he_cap; em_wifi7_agent_cap_t wifi7_cap; unsigned int num_op_classes; } em_radio_cap_info_t;
typedef struct { unsigned char before[RCU_GUARD]; em_radio_cap_info_t info; unsigned char after[RCU_GUARD]; } box_t;
typedef enum { dm_orch_type_none = 0, dm_orch_type_db_insert = 1, dm_orch_type_db_update = 2, dm_orch_type_db_delete = 3 } dm_orch_type_t;

class dm_easy_mesh_t { public: static char *macbytes_to_string(mac_address_t mac, char *string); };
class db_client_t { public: int unused; };
/* the row functions only record what update_db hands them */
extern char g_key[64]; extern char g_wifi7[4096]; extern unsigned int g_nop; extern int g_calls;
class dm_radio_cap_list_t {
public:
    int insert_row(db_client_t &db, char *mac, em_ap_ht_cap_t ht, em_ap_vht_cap_t vht, em_ap_he_cap_t he, char *wifi7, unsigned int nop);
    int update_row(db_client_t &db, em_ap_ht_cap_t ht, em_ap_vht_cap_t vht, em_ap_he_cap_t he, char *wifi7, unsigned int nop, char *mac);
    int delete_row(db_client_t &db, char *mac);
    int update_db(db_client_t &db_client, dm_orch_type_t op, void *data);
};

typedef struct {
    const char *test_name;
    int op;                 /* dm_orch_type_t, 99 = unknown */
    int pattern;            /* wifi7_cap bytes: 0 all zero, 1 byte i = i % 251, 2 all 0xFF */
    bool null_data;
    int expect_ret;
    int expect_calls;       /* row function calls (0 or 1) */
    int expect_len;         /* strlen of the wifi7 string handed to the DB, -1 unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern box_t *g_box;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_radio_cap_update_db(void);
#endif

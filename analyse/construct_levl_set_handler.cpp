/*
 * TEST CASES / CONSTRUCTOR: construct_levl_set_handler
 * Caller-owned buffers: lsh_pdata_buf (the raw_data_t), lsh_name_buf (the
 * event_name) and lsh_str_buf (the string value p_data->raw_data.bytes) --
 * the name and the string are sized EXACTLY strlen+1 so any over-read runs
 * into the poisoned tail; the runner poisons the LSH_PAD tail of each.
 * Expected MAC for the good strings is AA:BB:CC:DD:EE:01.
 *
 * Cases: clientMac (colon form, 12-hex form, empty, wrong type, NULL bytes),
 * maxNumberCSIClients (ok / over max / wrong type), Duration (0 -> default,
 * set, wrong type), clientMacData (full, mac only, interval too low,
 * duration too low, empty, only separators, wrong type, NULL bytes), unknown
 * property, 250-char property name, null name, malloc failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lsh_pdata_buf[LSH_PDATA_SZ + LSH_PAD];
alignas(16) char lsh_name_buf[LSH_NAME_MAX + LSH_PAD];
alignas(16) char lsh_str_buf[LSH_STR_MAX + LSH_PAD];
size_t lsh_name_len, lsh_str_len;
int lsh_malloc_fail, lsh_push_calls;
levl_config_t lsh_pushed;

#define P "Device.WiFi.X_RDK_CSI_LEVL."
#define L250 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define STR 3
#define U32 7
/* mac check flag: 1 -> pushed clientMac must be AA:BB:CC:DD:EE:01, 2 -> must be all zero */
lv_lsh_test_case_t levl_set_handler_suite[] = {
    /* name              event_name              type  str                          u32 mf | ret push mac max dur int */
    { "mac_colon",        P "clientMac",           STR, "AA:BB:CC:DD:EE:01",          0, 0,   0, 1, 1, 0,   0,   0 },
    { "mac_plain12",      P "clientMac",           STR, "aabbccddee01",               0, 0,   0, 1, 1, 0,   0,   0 },
    { "mac_empty",        P "clientMac",           STR, "",                           0, 0,   0, 1, 2, 0,   0,   0 },
    { "mac_wrong_type",   P "clientMac",           U32, NULL,                         5, 0,   2, 0, 0, 0,   0,   0 },
    { "mac_null_bytes",   P "clientMac",           STR, NULL,                         0, 0,   2, 0, 0, 0,   0,   0 },
    { "max_ok",           P "maxNumberCSIClients", U32, NULL,                         3, 0,   0, 1, 0, 3,   0,   0 },
    { "max_over",         P "maxNumberCSIClients", U32, NULL,                         6, 0,   2, 0, 0, 0,   0,   0 },
    { "max_wrong_type",   P "maxNumberCSIClients", STR, "3",                          0, 0,   2, 0, 0, 0,   0,   0 },
    { "dur_zero",         P "Duration",            U32, NULL,                         0, 0,   0, 1, 0, 0,2000,   0 },
    { "dur_set",          P "Duration",            U32, NULL,                      5000, 0,   0, 1, 0, 0,5000,   0 },
    { "dur_wrong_type",   P "Duration",            STR, "5000",                       0, 0,   2, 0, 0, 0,   0,   0 },
    { "data_full",        P "clientMacData",       STR, "AA:BB:CC:DD:EE:01;200;1500", 0, 0,   0, 1, 1, 0,1500, 200 },
    { "data_mac_only",    P "clientMacData",       STR, "AA:BB:CC:DD:EE:01",          0, 0,   0, 1, 1, 0,   0,   0 },
    { "data_int_low",     P "clientMacData",       STR, "AA:BB:CC:DD:EE:01;50;1500",  0, 0,   2, 0, 0, 0,   0,   0 },
    { "data_dur_low",     P "clientMacData",       STR, "AA:BB:CC:DD:EE:01;200;500",  0, 0,   2, 0, 0, 0,   0,   0 },
    { "data_empty",       P "clientMacData",       STR, "",                           0, 0,   0, 1, 2, 0,   0,   0 },
    { "data_separators",  P "clientMacData",       STR, ";;;",                        0, 0,   0, 1, 2, 0,   0,   0 },
    { "data_wrong_type",  P "clientMacData",       U32, NULL,                         7, 0,   2, 0, 0, 0,   0,   0 },
    { "data_null_bytes",  P "clientMacData",       STR, NULL,                         0, 0,   2, 0, 0, 0,   0,   0 },
    { "unknown_param",    P "somethingElse",       U32, NULL,                         1, 0,   0, 1, 2, 0,   0,   0 },
    { "param_250",        P L250,                  U32, NULL,                         1, 0,   0, 1, 2, 0,   0,   0 },
    { "null_name",        NULL,                    U32, NULL,                         0, 0,   2, 0, 0, 0,   0,   0 },
    { "malloc_fail",      P "Duration",            U32, NULL,                      5000, 1,   1, 0, 0, 0,   0,   0 },
    { NULL, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_levl_set_handler_input(const lv_lsh_test_case_t *tc)
{
    memset(lsh_pdata_buf, 0, sizeof(lsh_pdata_buf));
    memset(lsh_name_buf, 0, sizeof(lsh_name_buf));
    memset(lsh_str_buf, 0, sizeof(lsh_str_buf));
    lsh_malloc_fail = tc->malloc_fail; lsh_push_calls = 0;
    memset(&lsh_pushed, 0, sizeof(lsh_pushed));

    lsh_name_len = 0;
    if (tc->name) { lsh_name_len = strlen(tc->name) + 1; memcpy(lsh_name_buf, tc->name, lsh_name_len); }

    /* raw_data_t layout (LP64): int data_type @0; union (u32 / bytes) @8; size_t len @16 */
    *(int *)&lsh_pdata_buf[0] = tc->data_type;
    lsh_str_len = 0;
    if (tc->data_type == 3) {
        if (tc->str) {
            lsh_str_len = strlen(tc->str) + 1;
            memcpy(lsh_str_buf, tc->str, lsh_str_len);
            *(void **)&lsh_pdata_buf[8] = lsh_str_buf;
        } else {
            *(void **)&lsh_pdata_buf[8] = NULL;
        }
    } else {
        *(unsigned int *)&lsh_pdata_buf[8] = tc->u32;
    }
}

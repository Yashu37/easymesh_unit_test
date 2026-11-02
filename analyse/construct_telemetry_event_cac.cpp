/*
 * TEST CASES / CONSTRUCTOR: construct_telemetry_event_cac
 *
 * deny_type / deny_reason / mac come from poisoned runner buffers. tec_band
 * selects which isVapHotspot* branch fires (0 = none -> early return).
 *
 * Cases: secure5g, open5g, secure6g, open6g, no-band (return), NULL mac
 * (return), and long deny_type/deny_reason/mac that exercise the snprintf
 * truncation into telemetry_buff[64] / telemetry_val[128].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   tec_slot_buff[TEC_BUFF_SZ + TEC_PAD];
char   tec_slot_val[TEC_VAL_SZ + TEC_PAD];
size_t tec_buff_len, tec_val_len;
char   tec_t2_marker[128], tec_t2_val[256];
int    tec_t2_calls, tec_band;
alignas(16) char tec_type_buf[64 + TEC_PAD];
alignas(16) char tec_reason_buf[64 + TEC_PAD];
alignas(16) char tec_mac_buf[32 + TEC_PAD];

telemetry_event_cac_test_case_t telemetry_event_cac_suite[] = {
    /* name          band  deny_type  deny_reason  mac                 null_mac  expect_t2 */
    { "secure5g",     1,   "DENY",    "acl",       "aa:bb:cc:dd:ee:ff",  0,       1 },
    { "open5g",       2,   "DENY",    "acl",       "aa:bb:cc:dd:ee:ff",  0,       1 },
    { "secure6g",     3,   "DENY",    "acl",       "aa:bb:cc:dd:ee:ff",  0,       1 },
    { "open6g",       4,   "DENY",    "acl",       "aa:bb:cc:dd:ee:ff",  0,       1 },
    { "no_band",      0,   "DENY",    "acl",       "aa:bb:cc:dd:ee:ff",  0,       0 },
    { "null_mac",     1,   "DENY",    "acl",       "",                   1,       0 },
    { "long_fields",  1,   "LONGTYPEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "LONGREASONYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY", "aa:bb:cc:dd:ee:ff", 0, 1 },

    { NULL, 0, NULL, NULL, NULL, 0, 0 }  /* sentinel */
};

void construct_telemetry_event_cac_input(const telemetry_event_cac_test_case_t *tc)
{
    memset(tec_type_buf, 0, sizeof(tec_type_buf));
    memset(tec_reason_buf, 0, sizeof(tec_reason_buf));
    memset(tec_mac_buf, 0, sizeof(tec_mac_buf));
    snprintf(tec_type_buf, 64, "%s", tc->deny_type);
    snprintf(tec_reason_buf, 64, "%s", tc->deny_reason);
    if (!tc->null_mac) snprintf(tec_mac_buf, 32, "%s", tc->mac);

    tec_band = tc->band;
    tec_buff_len = tec_val_len = 0;
    tec_t2_calls = 0;
    tec_t2_marker[0] = tec_t2_val[0] = 0;
}

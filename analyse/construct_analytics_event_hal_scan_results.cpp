/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_scan_results
 *
 * arg is a scan_results_t at the start of asr_arg_buf (bytes past its size
 * poisoned by the runner).
 *
 * Cases: arg NULL, a normal result, zero results, MAX_SCANNED_VAPS (200),
 * radio_index UINT_MAX with num 0x80000000 (prints INT_MIN -> longest
 * string), and num UINT_MAX (prints -1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   asr_slot[ASR_SLOT_SZ + ASR_PAD];
size_t asr_len;
int    asr_calls;
alignas(16) char asr_arg_buf[sizeof(scan_results_t) + ASR_PAD];

analytics_event_hal_scan_results_test_case_t analytics_event_hal_scan_results_suite[] = {
    /* name               arg_null radio_index  num           ret calls len */
    { "arg_null",            1,      0,          0,            -1,   0,   0 },
    { "normal",              0,      1,          12,            0,   1,  20 },
    { "zero_results",        0,      0,          0,             0,   1,  19 },
    { "max_scanned_200",     0,      2,          200,           0,   1,  21 },
    { "longest_string",      0,   UINT_MAX,      0x80000000u,   0,   1,  38 },
    { "num_uint_max",        0,      0,          UINT_MAX,      0,   1,  20 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_analytics_event_hal_scan_results_input(const analytics_event_hal_scan_results_test_case_t *tc)
{
    memset(asr_arg_buf, 0, sizeof(asr_arg_buf));
    scan_results_t *r = (scan_results_t *)asr_arg_buf;
    r->radio_index = tc->radio_index;
    r->num = tc->num;
    asr_len = 0;
    asr_calls = 0;
}

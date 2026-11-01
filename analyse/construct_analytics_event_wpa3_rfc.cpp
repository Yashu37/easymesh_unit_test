/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_wpa3_rfc
 *
 * arg is one bool at the start of awr_arg_buf (bytes past sizeof(bool)
 * poisoned by the runner).
 *
 * Cases: rfc true -> "True", rfc false -> "False".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   awr_slot[AWR_SLOT_SZ + AWR_PAD];
size_t awr_len;
alignas(16) char awr_arg_buf[sizeof(bool) + AWR_PAD];

analytics_event_wpa3_rfc_test_case_t analytics_event_wpa3_rfc_suite[] = {
    /* name          rfc     expect   */
    { "rfc_true",    true,   "True"   },
    { "rfc_false",   false,  "False"  },

    { NULL, false, NULL }  /* sentinel */
};

void construct_analytics_event_wpa3_rfc_input(const analytics_event_wpa3_rfc_test_case_t *tc)
{
    memset(awr_arg_buf, 0, sizeof(awr_arg_buf));
    *(bool *)awr_arg_buf = tc->rfc;
    awr_len = 0;
}

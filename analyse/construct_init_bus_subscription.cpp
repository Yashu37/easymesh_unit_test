/*
 * TEST CASES / CONSTRUCTOR: construct_init_bus_subscription
 * bus_handle at ibs_bh_buf; p_app at ibs_app_buf (data.u.csi_analytics.
 * csi_session_index chosen per case). Stub flags select bus_open / add_row /
 * subscription outcomes.
 * Cases: open-fail, session already set (skip block), add-row fail, success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   ibs_slot[IBS_NAME_SZ + IBS_PAD];
size_t ibs_name_len;
char   ibs_sub_name[256];
int    ibs_open_fail, ibs_addrow_fail, ibs_sub_fail, ibs_added_index;
int    ibs_close_calls, ibs_sub_calls, ibs_timer_calls;
alignas(16) char ibs_bh_buf[16 + IBS_PAD];
alignas(16) char ibs_app_buf[sizeof(wifi_app_t) + IBS_PAD];

init_bus_subscription_test_case_t init_bus_subscription_suite[] = {
    /* name          session  open_fail addrow_fail sub_fail  expect_ret */
    { "open_fail",     0,      1,        0,          0,        1  },
    { "session_set",   5,      0,        0,          0,        0  },  /* skip the add/sub block */
    { "addrow_fail",   0,      0,        1,          0,        0  },  /* add fails -> close -> rc(success from close) */
    { "success",       0,      0,        0,          0,        0  },
    { NULL, 0, 0, 0, 0, 0 }
};

void construct_init_bus_subscription_input(const init_bus_subscription_test_case_t *tc)
{
    memset(ibs_bh_buf, 0, sizeof(ibs_bh_buf));
    memset(ibs_app_buf, 0, sizeof(ibs_app_buf));
    ((wifi_app_t *)ibs_app_buf)->data.u.csi_analytics.csi_session_index = tc->session;
    ibs_open_fail = tc->open_fail; ibs_addrow_fail = tc->addrow_fail; ibs_sub_fail = tc->sub_fail;
    ibs_added_index = 3;
    ibs_close_calls = ibs_sub_calls = ibs_timer_calls = 0;
    ibs_name_len = 0; ibs_sub_name[0] = 0;
}

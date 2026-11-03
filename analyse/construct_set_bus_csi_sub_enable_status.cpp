/*
 * TEST CASES / CONSTRUCTOR: construct_set_bus_csi_sub_enable_status
 * bus_handle at ses_bh_buf (poison past 16). Cases: enable success, disable
 * success, bus failure, large session index.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   ses_slot[SES_NAME_SZ + SES_PAD];
size_t ses_name_len;
char   ses_name_seen[256];
int    ses_set_calls, ses_fail, ses_last_bool;
alignas(16) char ses_bh_buf[16 + SES_PAD];

set_bus_csi_sub_enable_status_test_case_t set_bus_csi_sub_enable_status_suite[] = {
    /* name          session  status fail  expect_ret */
    { "enable_ok",     1,      1,    0,     0  },
    { "disable_ok",    2,      0,    0,     0  },
    { "bus_fail",      3,      1,    1,     1  },
    { "big_session",   888888, 1,    0,     0  },
    { NULL, 0, 0, 0, 0 }
};

void construct_set_bus_csi_sub_enable_status_input(const set_bus_csi_sub_enable_status_test_case_t *tc)
{
    memset(ses_bh_buf, 0, sizeof(ses_bh_buf));
    ses_fail = tc->fail;
    ses_name_len = 0; ses_name_seen[0] = 0; ses_set_calls = 0; ses_last_bool = -1;
}

/*
 * TEST CASES / CONSTRUCTOR: construct_dpp_mac_str_tmp
 *
 * dpp_mac_str_tmp(mac) formats a 6-byte MAC into "XX:XX:XX:XX:XX:XX".
 * Cases exercise a few MAC values; the 6-byte input lives in a runner-owned
 * buffer whose tail is poisoned by the runner so any read past mac[5] is
 * caught.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

uint8_t     dmt_mac[16];        /* backing; only first 6 bytes valid, rest poisoned */
const char *dmt_case_name;
const char *dmt_expect;         /* expected formatted string */

dpp_mac_test_case_t dpp_mac_suite[] = {
    /* name            b0    b1    b2    b3    b4    b5     expected            */
    { "all_zero",      {0x00,0x00,0x00,0x00,0x00,0x00}, "00:00:00:00:00:00" },
    { "typical",       {0xaa,0xbb,0xcc,0xdd,0xee,0xff}, "AA:BB:CC:DD:EE:FF" },
    { "all_ff",        {0xff,0xff,0xff,0xff,0xff,0xff}, "FF:FF:FF:FF:FF:FF" },
    { "mixed",         {0x01,0x23,0x45,0x67,0x89,0xab}, "01:23:45:67:89:AB" },

    { NULL, {0,0,0,0,0,0}, NULL }  /* sentinel */
};

void construct_dpp_mac_str_tmp_input(const dpp_mac_test_case_t *tc)
{
    dmt_case_name = tc->test_name;
    dmt_expect    = tc->expected;
    memset(dmt_mac, 0xEE, sizeof(dmt_mac));   /* fill, then set the 6 real bytes */
    for (int i = 0; i < 6; i++) dmt_mac[i] = tc->mac[i];
}

/*
 * TEST CASES / CONSTRUCTOR: construct_harvester_str_to_mac_bytes
 * key lives in hsm_key_buf (runner poisons past its NUL); bmac in hsm_bmac_buf
 * (pre-filled 0xEE, runner poisons past the 6-byte mac).
 * Cases: colon_fmt (17 chars), plain_fmt (12 chars), empty_key (bmac untouched).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char          hsm_key_buf[64 + HSM_PAD];
unsigned char hsm_bmac_buf[6 + HSM_PAD];

harv_hsm_test_case_t harvester_str_to_mac_bytes_suite[] = {
    /* name        key                    expect_changed e0   e1   e2   e3   e4   e5 */
    { "colon_fmt", "aa:bb:cc:dd:ee:ff",   1, {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "plain_fmt", "112233445566",        1, {0x11,0x22,0x33,0x44,0x55,0x66} },
    { "empty_key", "",                    0, {0xEE,0xEE,0xEE,0xEE,0xEE,0xEE} },
    { NULL, NULL, 0, {0} }  /* sentinel */
};

void construct_harvester_str_to_mac_bytes_input(const harv_hsm_test_case_t *tc)
{
    memset(hsm_key_buf, 0, sizeof(hsm_key_buf));
    memset(hsm_bmac_buf, 0xEE, sizeof(hsm_bmac_buf));
    snprintf(hsm_key_buf, 64, "%s", tc->key);
}

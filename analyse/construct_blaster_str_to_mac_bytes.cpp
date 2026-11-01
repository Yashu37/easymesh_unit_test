/*
 * TEST CASES / CONSTRUCTOR: construct_blaster_str_to_mac_bytes
 *
 * key is copied into bsm_key_buf (runner poisons past strlen+1); bmac is
 * MAC_ADDR_LEN bytes at the start of bsm_mac_buf (poisoned past 6).
 *
 * Cases: colon form, upper-case colon form, 12-hex form, empty key
 * (bmac untouched), and a longer colon string (extra text ignored).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char bsm_key_buf[BSM_KEY_MAX + BSM_PAD];
alignas(16) unsigned char bsm_mac_buf[MAC_ADDR_LEN + BSM_PAD];

blaster_str_to_mac_bytes_test_case_t blaster_str_to_mac_bytes_suite[] = {
    /* name           key                              expect bmac                          */
    { "colon_form",   "10:11:12:13:14:15",             {0x10,0x11,0x12,0x13,0x14,0x15} },
    { "colon_upper",  "AA:BB:CC:DD:EE:FF",             {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "hex12_form",   "a0a1a2a3a4a5",                  {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5} },
    { "empty_key",    "",                              {0x77,0x77,0x77,0x77,0x77,0x77} },  /* untouched */
    { "colon_extra",  "01:02:03:04:05:06:07:08:09",    {0x01,0x02,0x03,0x04,0x05,0x06} },

    { NULL, NULL, {0} }  /* sentinel */
};

void construct_blaster_str_to_mac_bytes_input(const blaster_str_to_mac_bytes_test_case_t *tc)
{
    memset(bsm_key_buf, 0, sizeof(bsm_key_buf));
    snprintf(bsm_key_buf, BSM_KEY_MAX, "%s", tc->key);
    memset(bsm_mac_buf, 0x77, sizeof(bsm_mac_buf));
}

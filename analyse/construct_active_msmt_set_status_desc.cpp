/*
 * TEST CASES / CONSTRUCTOR: construct_active_msmt_set_status_desc
 *
 * dst_mac is MAC_ADDRESS_LENGTH (13) bytes at the start of asd_mac_buf (as
 * the real DestMac field; runner poisons past 13). plan_id and msg are
 * strings in their own buffers (poisoned past their NULs; NULL when the
 * case wants the "?:" fallback). The stand-in holds status + status_desc.
 *
 * Cases: a raw 6-byte MAC (strlen<12 -> trimmed hex), a 12-char hex string
 * (strncpy branch), NULL plan_id / msg (?: ""), a long msg, status values
 * mapping to strings, and a MAC with no NUL in the first 6 bytes but a
 * terminator before byte 13.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   asd_slot_mac[ASD_MAC_SZ + ASD_PAD];
char   asd_slot_desc[ASD_DESC_SZ + ASD_PAD];
size_t asd_mac_len, asd_desc_len;
alignas(16) unsigned char asd_mac_buf[ASD_DSTMAC_SZ + ASD_PAD];
alignas(16) char asd_plan_buf[64 + ASD_PAD];
alignas(16) char asd_msg_buf[512 + ASD_PAD];
alignas(16) char asd_mgr_buf[sizeof(wifi_actvie_msmt_t) + ASD_PAD];

active_msmt_set_status_desc_test_case_t active_msmt_set_status_desc_suite[] = {
    /* name            dst_mac_kind plan_id       msg            status                        want_desc_prefix                              */
    { "raw_6byte_mac",   0, "PLAN1",     "hello",       ACTIVE_MSMT_STATUS_SUCCEED,  "Plan[PLAN1] Step[7] Mac[102030405060] FW[] Node[] Status[SUCCEED] hello" },
    { "hex12_string",    1, "PLAN2",     "world",       ACTIVE_MSMT_STATUS_FAILED,   "Plan[PLAN2] Step[7] Mac[aabbccddeeff] FW[] Node[] Status[FAILED] world"  },
    { "null_plan_msg",   0, NULL,        NULL,          ACTIVE_MSMT_STATUS_BUSY,     "Plan[] Step[7] Mac[102030405060] FW[] Node[] Status[BUSY] "             },
    { "long_msg",        0, "P",         "LONG",        ACTIVE_MSMT_STATUS_NO_CLIENT,"Plan[P] Step[7] Mac[102030405060] FW[] Node[] Status[NO_CLIENT] "        },
    { "status_undef",    0, "P",         "x",           ACTIVE_MSMT_STATUS_UNDEFINED,"Plan[P] Step[7] Mac[102030405060] FW[] Node[] Status[UNDEFINED] x"       },
    { "mac_zero_at_6",   2, "P",         "x",           ACTIVE_MSMT_STATUS_WRONG_ARG,"Plan[P] Step[7] Mac[aabbccddeeff] FW[] Node[] Status[WRONG_ARG] x"       },

    { NULL, 0, NULL, NULL, ACTIVE_MSMT_STATUS_SUCCEED, NULL }  /* sentinel */
};

void construct_active_msmt_set_status_desc_input(const active_msmt_set_status_desc_test_case_t *tc)
{
    memset(asd_mac_buf, 0, sizeof(asd_mac_buf));
    if (tc->dst_mac_kind == 1) {
        memcpy(asd_mac_buf, "aabbccddeeff", 12);           /* 12-char string -> strncpy branch */
    } else if (tc->dst_mac_kind == 2) {
        unsigned char m[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        memcpy(asd_mac_buf, m, 6);                          /* bytes 6..12 stay 0 (NUL at 6) */
    } else {
        unsigned char m[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(asd_mac_buf, m, 6);                          /* raw MAC, NUL at byte 6 */
    }

    memset(asd_plan_buf, 0, sizeof(asd_plan_buf));
    memset(asd_msg_buf, 0, sizeof(asd_msg_buf));
    if (tc->plan_id) snprintf(asd_plan_buf, 64, "%s", tc->plan_id);
    if (tc->msg) {
        if (!strcmp(tc->msg, "LONG")) memset(asd_msg_buf, 'z', 500), asd_msg_buf[500] = 0;
        else snprintf(asd_msg_buf, 512, "%s", tc->msg);
    }

    memset(asd_mgr_buf, 0, sizeof(asd_mgr_buf));
    ((wifi_actvie_msmt_t *)asd_mgr_buf)->status = tc->status;

    asd_mac_len = asd_desc_len = 0;
}

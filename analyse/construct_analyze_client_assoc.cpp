/*
 * TEST CASES / CONSTRUCTOR: construct_analyze_client_assoc
 *
 * The JSON is copied into ac_evt_buf = em_bus_event_t header + subdoc.buff
 * (runner poisons everything past the NUL). pcmd[] is ac_pcmd_buf with
 * EM_MAX_CMD usable slots (runner poisons slot EM_MAX_CMD onward).
 *
 * expect_num: 1 = accepted (cmd built, params checked), 0 = rejected,
 * -1 = JSON parse error. Accept cases also check bssid / AssocControl /
 * ValidityPeriod / sta_count / first STA. Cases marked [spec] are inputs a
 * strict MAC parser should reject (trailing text, sign, whitespace).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char ac_evt_buf[AC_EVT_SZ];
alignas(16) void *ac_pcmd_buf[EM_MAX_CMD + 8];

#define W(inner) "{\"wfa-dataelements:ClientAssocCtrlRequest\":{" inner "}}"
#define B1 "\"BSSID\":\"aa:bb:cc:dd:ee:ff\""
#define S1 "\"StaMacList\":[\"11:22:33:44:55:66\"]"
#define Z6 {0,0,0,0,0,0}
#define BB {0xaa,0xbb,0xcc,0xdd,0xee,0xff}
#define SS {0x11,0x22,0x33,0x44,0x55,0x66}

ac_test_case_t analyze_client_assoc_suite[] = {
 /* name                     json                                                                 gen num bssid  ac vp  cnt sta0 */
 /* ---- accepted ---- */
 {"ok_colon_basic",          W(B1 ",\"AssocControl\":0,\"ValidityPeriod\":30," S1),               0, 1, BB, 0, 30, 1, SS},
 {"ok_assoc_unblock",        W(B1 ",\"AssocControl\":1,\"ValidityPeriod\":5," S1),                0, 1, BB, 1, 5,  1, SS},
 {"ok_no_colon_bssid",       W("\"BSSID\":\"aabbccddeeff\"," S1),                                 0, 1, BB, 0, 0,  1, SS},
 {"ok_upper_case",           W("\"BSSID\":\"AA:BB:CC:DD:EE:FF\",\"StaMacList\":[\"11:22:33:44:55:66\"]"), 0, 1, BB, 0, 0, 1, SS},
 {"ok_optionals_absent",     W(B1 "," S1),                                                        0, 1, BB, 0, 0,  1, SS},
 {"ok_vp_max_65535",         W(B1 ",\"ValidityPeriod\":65535," S1),                               0, 1, BB, 0, 65535, 1, SS},
 {"ok_vp_zero",              W(B1 ",\"ValidityPeriod\":0," S1),                                   0, 1, BB, 0, 0,  1, SS},
 {"ok_sta_no_colon",         W(B1 ",\"StaMacList\":[\"112233445566\"]"),                          0, 1, BB, 0, 0,  1, SS},
 {"ok_mixed_sta_forms",      W(B1 ",\"StaMacList\":[\"11:22:33:44:55:66\",\"aabbccddeeff\",\"01:02:03:04:05:06\"]"), 0, 1, BB, 0, 0, 3, SS},
 {"ok_sta_count_20_max",     NULL,                                                                2, 1, BB, 0, 0, 20, SS},
 {"ok_extra_unknown_field",  W(B1 ",\"Foo\":123," S1),                                            0, 1, BB, 0, 0,  1, SS},
 {"ok_zero_mac_values",      W("\"BSSID\":\"00:00:00:00:00:00\",\"StaMacList\":[\"00:00:00:00:00:00\"]"), 0, 1, Z6, 0, 0, 1, Z6},
 /* ---- JSON / envelope ---- */
 {"rej_invalid_json",        "{\"wfa-dataelements:ClientAssocCtrlRequest\":{",                    0, -1, Z6, 0, 0, 0, Z6},
 {"rej_empty_string",        "",                                                                  0, -1, Z6, 0, 0, 0, Z6},
 {"rej_not_object_array",    "[1,2,3]",                                                           0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_missing_wfa_key",     "{\"foo\":{}}",                                                      0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_wfa_key_null",        "{\"wfa-dataelements:ClientAssocCtrlRequest\":null}",                0, 0,  Z6, 0, 0, 0, Z6},
 /* ---- BSSID ---- */
 {"rej_bssid_missing",       W(S1),                                                               0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_number",        W("\"BSSID\":123," S1),                                              0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_empty",         W("\"BSSID\":\"\"," S1),                                             0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_short_colon",   W("\"BSSID\":\"aa:bb:cc\"," S1),                                     0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_nonhex",        W("\"BSSID\":\"zz:bb:cc:dd:ee:ff\"," S1),                            0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_short_nocolon", W("\"BSSID\":\"aabbccddee\"," S1),                                   0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_trailing [spec]", W("\"BSSID\":\"aa:bb:cc:dd:ee:ff:11\"," S1),                       0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_garbage [spec]",  W("\"BSSID\":\"aa:bb:cc:dd:ee:ffxyz\"," S1),                       0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_minus [spec]",  W("\"BSSID\":\"-1:bb:cc:dd:ee:ff\"," S1),                            0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_leading_ws [spec]", W("\"BSSID\":\" aa:bb:cc:dd:ee:ff\"," S1),                       0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_bssid_long_5000",     NULL,                                                                3, 0,  Z6, 0, 0, 0, Z6},
 /* ---- AssocControl / ValidityPeriod ---- */
 {"rej_assoc_string",        W(B1 ",\"AssocControl\":\"1\"," S1),                                 0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_assoc_two",           W(B1 ",\"AssocControl\":2," S1),                                     0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_assoc_negative",      W(B1 ",\"AssocControl\":-1," S1),                                    0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_assoc_fraction",      W(B1 ",\"AssocControl\":0.5," S1),                                   0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_vp_string",           W(B1 ",\"ValidityPeriod\":\"30\"," S1),                              0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_vp_negative",         W(B1 ",\"ValidityPeriod\":-1," S1),                                  0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_vp_65536",            W(B1 ",\"ValidityPeriod\":65536," S1),                               0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_vp_fraction",         W(B1 ",\"ValidityPeriod\":1.5," S1),                                 0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_vp_huge_1e30",        W(B1 ",\"ValidityPeriod\":1e30," S1),                                0, 0,  Z6, 0, 0, 0, Z6},
 /* ---- StaMacList ---- */
 {"rej_stalist_missing",     W(B1),                                                               0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_stalist_object",      W(B1 ",\"StaMacList\":{\"a\":1}"),                                   0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_stalist_string",      W(B1 ",\"StaMacList\":\"11:22:33:44:55:66\""),                       0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_stalist_empty",       W(B1 ",\"StaMacList\":[]"),                                          0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_stalist_21_over_max", NULL,                                                                1, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_non_string",      W(B1 ",\"StaMacList\":[123]"),                                       0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_null_entry",      W(B1 ",\"StaMacList\":[null]"),                                      0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_bad_second",      W(B1 ",\"StaMacList\":[\"11:22:33:44:55:66\",\"zz\"]"),              0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_short",           W(B1 ",\"StaMacList\":[\"11:22:33\"]"),                              0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_empty_string",    W(B1 ",\"StaMacList\":[\"\"]"),                                      0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_trailing [spec]", W(B1 ",\"StaMacList\":[\"11:22:33:44:55:66:77\"]"),                  0, 0,  Z6, 0, 0, 0, Z6},
 {"rej_sta_long_3000",       NULL,                                                                4, 0,  Z6, 0, 0, 0, Z6},

 { NULL, NULL, 0, 0, Z6, 0, 0, 0, Z6 }  /* sentinel */
};

void construct_analyze_client_assoc_input(const ac_test_case_t *tc)
{
    em_bus_event_t *evt = (em_bus_event_t *)ac_evt_buf;
    char *buff = evt->u.subdoc.buff;
    char *tmp = (char *)malloc(AC_BUF_MAX);
    memset(ac_evt_buf, 0, AC_EVT_SZ);
    memset(ac_pcmd_buf, 0, sizeof(ac_pcmd_buf));

    if (tc->gen == 0) {
        snprintf(tmp, AC_BUF_MAX, "%s", tc->json);
    } else if (tc->gen == 1 || tc->gen == 2) {
        int n = (tc->gen == 1) ? 21 : 20, off = 0;
        off += snprintf(tmp + off, AC_BUF_MAX - off, "{\"wfa-dataelements:ClientAssocCtrlRequest\":{\"BSSID\":\"aa:bb:cc:dd:ee:ff\",\"StaMacList\":[");
        for (int i = 0; i < n; i++)
            off += snprintf(tmp + off, AC_BUF_MAX - off, "%s\"11:22:33:44:55:%02x\"", i ? "," : "", i);
        snprintf(tmp + off, AC_BUF_MAX - off, "]}}");
    } else if (tc->gen == 3) {
        int off = snprintf(tmp, AC_BUF_MAX, "{\"wfa-dataelements:ClientAssocCtrlRequest\":{\"BSSID\":\"");
        for (int i = 0; i < 5000; i++) tmp[off++] = (i % 3 == 2) ? ':' : 'a';
        snprintf(tmp + off, AC_BUF_MAX - off, "\",\"StaMacList\":[\"11:22:33:44:55:66\"]}}");
    } else {
        int off = snprintf(tmp, AC_BUF_MAX, "{\"wfa-dataelements:ClientAssocCtrlRequest\":{\"BSSID\":\"aa:bb:cc:dd:ee:ff\",\"StaMacList\":[\"");
        for (int i = 0; i < 3000; i++) tmp[off++] = '1';
        snprintf(tmp + off, AC_BUF_MAX - off, "\"]}}");
    }
    snprintf(buff, AC_BUF_MAX, "%s", tmp);
    evt->data_len = (unsigned int)strlen(buff);
    free(tmp);
}

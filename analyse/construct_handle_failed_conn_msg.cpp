/*
 * TEST CASES / CONSTRUCTOR: construct_handle_failed_conn_msg
 *
 * The message (22-byte header: raw hdr + CMDU, then the TLVs of the case) is built into msg_store at
 * offset HFC_LEFT, EXACTLY len bytes long: the runner poisons the bytes in front of it and everything past
 * its end, so a read beyond the message is an ASan report. A TLV is {type, length field, value, bytes really
 * present}. Values: BSSID 02:00:00:00:00:aa, STA 02:00:00:00:00:bb, status 0x0010 (16), reason 0x0007 (7),
 * second status 0x0020 (32). The recorded output is the published FailedConnectionEvent JSON with the
 * whitespace stripped.
 *
 * em_msg_t::validate() only checks the FIRST TLV of each type, so a later duplicate TLV with a short length
 * field reaches the parsing loop: memcpy(bssid / sta_mac, tlv->value, 6) and sc->status_code then read bytes
 * that are not part of that TLV. Cases marked [spec] were wrong behaviour (a later short duplicate
 * overrides the good value with the bytes that follow it, inside the buffer: no abort). The rej_dup_*_before_eom
 * cases (a short duplicate BSSID / STA TLV directly in front of the EOM TLV) read past the end of the buffer
 * and ABORTED on the original handler. With fix 1 a TLV shorter than its value is ignored (first values
 * kept) and all of the rej_dup_* cases pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "handle_failed_conn_msg.h"

namespace hfc {

alignas(16) unsigned char msg_store[HFC_LEFT + HFC_MSG_SZ + HFC_PAD];
unsigned int g_len = 0;
unsigned char *g_msg = NULL;

static const unsigned char BSSID[6] = {2, 0, 0, 0, 0, 0xaa};
static const unsigned char STA[6]   = {2, 0, 0, 0, 0, 0xbb};
static const unsigned char SCODE[4] = {0x00, 0x10, 0xde, 0xad};
static const unsigned char SCODE2[2] = {0x00, 0x20};
static const unsigned char RCODE[3] = {0x00, 0x07, 0xff};
static const unsigned char JUNK[8]  = {1, 2, 3, 4, 5, 6, 7, 8};

#define TB  {0xb8, 6, BSSID, 6}
#define TS  {0x95, 6, STA, 6}
#define TC  {0xc9, 2, SCODE, 2}
#define TR  {0xca, 2, RCODE, 2}
#define TE  {0x00, 0, NULL, 0}
#define TX  {0xff, 0, NULL, 0}
#define BS  "\"BSSID\":\"02:00:00:00:00:aa\""
#define MC  "\"MACAddress\":\"02:00:00:00:00:bb\""
/* {name, {tlvs}, cut, short_len, no_desc, pub_fail, expect_pub, has, not_has, crash} */

test_case_t suite[] = {
 /* ---- valid messages ---- */
 {"ok_bssid", {TB, TS, TC, TR, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"ok_mac", {TB, TS, TC, TR, TE, TX}, 0, 0, false, false, 1, MC, NULL, false},
 {"ok_status", {TB, TS, TC, TR, TE, TX}, 0, 0, false, false, 1, "\"StatusCode\":16", NULL, false},
 {"ok_reason", {TB, TS, TC, TR, TE, TX}, 0, 0, false, false, 1, "\"ReasonCode\":7", NULL, false},
 {"ok_timestamp", {TB, TS, TC, TR, TE, TX}, 0, 0, false, false, 1, "Z\"}", NULL, false},
 {"ok_no_reason", {TB, TS, TC, TE, TX}, 0, 0, false, false, 1, "\"ReasonCode\":0", NULL, false},
 {"ok_reason_len1_ignored", {TB, TS, TC, {0xca, 1, RCODE, 1}, TE, TX}, 0, 0, false, false, 1, "\"ReasonCode\":0", NULL, false},
 {"ok_reason_len3", {TB, TS, TC, {0xca, 3, RCODE, 3}, TE, TX}, 0, 0, false, false, 1, "\"ReasonCode\":7", NULL, false},
 {"ok_unknown_tlv_skipped", {{0x55, 8, JUNK, 8}, TB, TS, TC, TE, TX}, 0, 0, false, false, 1, "\"StatusCode\":16", NULL, false},
 {"ok_order_reversed", {TC, TS, TB, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"ok_status_len4", {TB, TS, {0xc9, 4, SCODE, 4}, TE, TX}, 0, 0, false, false, 1, "\"StatusCode\":16", NULL, false},
 {"ok_bssid_len8", {{0xb8, 8, JUNK, 8}, TS, TC, TE, TX}, 0, 0, false, false, 1, "\"BSSID\":\"01:02:03:04:05:06\"", NULL, false},
 {"ok_dup_status_last_wins", {TB, TS, TC, {0xc9, 2, SCODE2, 2}, TE, TX}, 0, 0, false, false, 1, "\"StatusCode\":32", NULL, false},
 {"ok_stop_at_eom", {TB, TS, TC, TE, TR, TX}, 0, 0, false, false, 1, "\"ReasonCode\":0", NULL, false},
 {"ok_no_bus_descriptor", {TB, TS, TC, TE, TX}, 0, 0, true, false, 0, NULL, NULL, false},
 {"ok_publish_failure", {TB, TS, TC, TE, TX}, 0, 0, false, true, 1, "\"StatusCode\":16", NULL, false},
 /* ---- rejected (nothing published) ---- */
 {"rej_missing_bssid", {TS, TC, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_missing_sta", {TB, TC, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_missing_status", {TB, TS, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_only_eom", {TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_bssid_len5", {{0xb8, 5, BSSID, 5}, TS, TC, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_sta_len5", {TB, {0x95, 5, STA, 5}, TC, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_status_len1", {TB, TS, {0xc9, 1, SCODE, 1}, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_no_eom", {TB, TS, TC, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_empty_message", {TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_len_below_header", {TB, TS, TC, TE, TX}, 0, 10, false, false, 0, NULL, NULL, false},
 {"rej_len_header_minus_1", {TB, TS, TC, TE, TX}, 0, 21, false, false, 0, NULL, NULL, false},
 {"rej_tlv_length_overflows", {{0xb8, 100, BSSID, 6}, TS, TC, TE, TX}, 0, 0, false, false, 0, NULL, NULL, false},
 {"rej_message_truncated_eom_cut", {TB, TS, TC, TE, TX}, 3, 0, false, false, 0, NULL, NULL, false},
 {"rej_message_truncated_mid_tlv", {TB, TS, TC, TE, TX}, 6, 0, false, false, 0, NULL, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort (a later short duplicate overrides the good value) ---- */
 {"rej_dup_status_len0_overrides", {TB, TS, TC, {0xc9, 0, NULL, 0}, TE, TX}, 0, 0, false, false, 1, "\"StatusCode\":16", NULL, false},
 {"rej_dup_bssid_len0_mid_overrides", {TB, TS, TC, {0xb8, 0, NULL, 0}, TR, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"rej_dup_sta_len0_mid_overrides", {TB, TS, TC, {0x95, 0, NULL, 0}, TR, TE, TX}, 0, 0, false, false, 1, MC, NULL, false},
 /* ---- were CRASH cases on the original handler: a short duplicate TLV in front of the EOM (now ignored) ---- */
 {"rej_dup_bssid_len0_before_eom", {TB, TS, TC, {0xb8, 0, NULL, 0}, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"rej_dup_bssid_len1_before_eom", {TB, TS, TC, {0xb8, 1, BSSID, 1}, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"rej_dup_bssid_len2_before_eom", {TB, TS, TC, {0xb8, 2, BSSID, 2}, TE, TX}, 0, 0, false, false, 1, BS, NULL, false},
 {"rej_dup_sta_len0_before_eom", {TB, TS, TC, {0x95, 0, NULL, 0}, TE, TX}, 0, 0, false, false, 1, MC, NULL, false},

 { NULL, {TX}, 0, 0, false, false, 0, NULL, NULL, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(msg_store, 0, sizeof(msg_store));
    unsigned char *p = msg_store + HFC_LEFT;
    unsigned int n = 22;                           /* em_raw_hdr_t (14) + em_cmdu_t (8) */
    for (int i = 0; i < HFC_MAXTLV && tc->tlvs[i].type != 0xff; i++) {
        const tlv_spec_t *t = &tc->tlvs[i];
        p[n++] = t->type;
        p[n++] = (unsigned char)(t->len >> 8); p[n++] = (unsigned char)(t->len & 0xff);
        if (t->nval && t->val) { memcpy(p + n, t->val, t->nval); n += t->nval; }
    }
    g_msg = p;
    g_len = tc->short_len > 0 ? (unsigned int)tc->short_len : n - tc->cut;
    g_npub = 0; g_pub[0] = '\0';
    g_no_desc = tc->no_desc; g_pub_fail = tc->pub_fail;
}

void teardown(void) { g_msg = NULL; }

} /* namespace hfc */

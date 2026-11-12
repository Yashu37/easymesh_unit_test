/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppTestFrameHandler
 *
 * wifi_dppTestFrameHandler(arg): thread routine of the DPP test frame receiver.  Inputs crossed: /nvram/wifiDppTest not readable, create_test_socket() failing, select timing out once or recvfrom failing once, a
 * select that keeps failing, 0-3 datagrams from the test socket, each with a valid / wrong 8-byte signature, a TLV list (command, vap name, station mac, raw frame - in any order, any may be missing) and
 * per-TLV lengths: command 4 / 5 / 64, vap name 5 / 31 / 33 / 200, mac 6 / 7 / 100, raw 0 / 1 / 20 / 900 / 1000, a vap name that is not "ath<N>", the chirp / reconfig auth response / anqp / mgmt commands, a
 * datagram of exactly 1024 bytes made of filler TLVs, a datagram shorter than the signature and a truncated datagram that follows a complete one (the stale bytes of the previous datagram are still in the buffer).
 * Expected (CORRECT behaviour): file not readable or socket creation failure -> returns NULL at once (nothing closed); otherwise the loop keeps running; a select that fails (not a timeout) ends the loop, closes the
 * socket and returns NULL; for every datagram with the signature, the chirp or reconfig auth response command (a 4-byte TLV), a vap name of the form "ath<N>" (N parsed, at most 31 characters), a 6-byte mac and a raw
 * frame that lies inside the received bytes, mgmt_frame_received_callback is called once with that ap index, mac, the raw bytes, type ACTION, direction uplink and the raw TLV length as frame length; datagrams that
 * do not qualify - wrong signature, other command, a missing TLV, a name that is not "ath<N>", a datagram shorter than the signature, a TLV that is not completely inside the received bytes - and TLVs whose length
 * does not fit the local buffers are rejected WITHOUT writing outside the buffers and without reading beyond the received datagram; a timeout or a failed recvfrom just continues.
 * Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wtd.h"

#define CMD(l)   { 0, l, 0 }
#define REC(l)   { 0, l, 1 }
#define VAP(l,n) { 1, l, n }
#define MAC(l)   { 2, l, 7 }
#define RAW(l)   { 4, l, 9 }
#define OK3(n)   { 1, 4, { CMD(4), VAP(5,n), MAC(6), RAW(20) }, 0, 0 }
/* sig_ok, n, { {type, len, val} ... }, total, cut */
/* name, ndg, { dgrams }, socket_fail, noaccess, selfail, sel0, recvfail, chk_len, last */
hwr_wtd_case_t sg_wifi_dppTestFrameHandler_suite[] = {
	{ "valid_chirp_ap3",                 1, { OK3(3) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "valid_chirp_ap0",                 1, { OK3(0) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "valid_chirp_ap15",                1, { OK3(15) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "valid_reconf_auth_resp_ap2",      1, { { 1, 4, { REC(4), VAP(5,2), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "raw_len_0",                       1, { { 1, 4, { CMD(4), VAP(5,1), MAC(6), RAW(0) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "raw_len_1",                       1, { { 1, 4, { CMD(4), VAP(5,1), MAC(6), RAW(1) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "raw_len_900",                     1, { { 1, 4, { CMD(4), VAP(5,1), MAC(6), RAW(900) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_len_31",                 1, { { 1, 4, { CMD(4), VAP(31,2), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "tlvs_in_other_order",             1, { { 1, 4, { RAW(20), MAC(6), VAP(5,4), CMD(4) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "wrong_signature_ignored",         1, { { 0, 4, { CMD(4), VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "command_anqp_ignored",            1, { { 1, 4, { { 0, 4, 2 }, VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "command_mgmt_ignored",            1, { { 1, 4, { { 0, 4, 3 }, VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "command_tlv_missing",             1, { { 1, 3, { VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_tlv_missing",            1, { { 1, 3, { CMD(4), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "mac_tlv_missing",                 1, { { 1, 3, { CMD(4), VAP(5,3), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "raw_tlv_missing",                 1, { { 1, 3, { CMD(4), VAP(5,3), MAC(6) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "two_valid_datagrams",             2, { OK3(1), OK3(2) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "bad_then_valid",                  2, { { 0, 4, { CMD(4), VAP(5,3), MAC(6), RAW(20) }, 0, 0 }, OK3(5) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "valid_then_bad_then_valid",       3, { OK3(1), { 1, 3, { VAP(5,3), MAC(6), RAW(20) }, 0, 0 }, OK3(6) }, 0, 0, 0, 0, 0, 0, 0 },
	{ "datagram_shorter_than_signature", 1, { { 1, 0, {}, 0, 4 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "signature_only_datagram",         1, { { 1, 0, {}, 0, 8 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "select_timeout_then_valid",       1, { OK3(2) }, 0, 0, 0, 1, 0, 0, 0 },
	{ "recvfrom_fails_then_valid",       1, { OK3(2) }, 0, 0, 0, 0, 1, 0, 0 },
	{ "debug_file_missing_returns_null", 1, { OK3(2) }, 0, 1, 0, 0, 0, 0, 0 },
	{ "socket_fails_returns_null",       1, { OK3(2) }, 1, 0, 0, 0, 0, 0, 0 },
	{ "callback_gets_frame_length",      1, { OK3(3) }, 0, 0, 0, 0, 0, 1, 0 },
	/* output that is wrong although the original does not crash */
	{ "select_error_ends_loop",          0, {}, 0, 0, 1, 0, 0, 0, 0 },
	{ "vap_name_not_ath_format",         1, { { 1, 4, { CMD(4), VAP(5,-1), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 },
	{ "truncated_datagram_replays_stale",2, { OK3(3), { 1, 4, { CMD(4), VAP(5,3), MAC(6), RAW(20) }, 0, 37 } }, 0, 0, 0, 0, 0, 0, 0 },
	/* inputs that crash the original: run LAST */
	{ "command_tlv_len_5",               1, { { 1, 4, { CMD(5), VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "command_tlv_len_64",              1, { { 1, 4, { CMD(64), VAP(5,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "vap_name_len_33",                 1, { { 1, 4, { CMD(4), VAP(33,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "vap_name_len_200",                1, { { 1, 4, { CMD(4), VAP(200,3), MAC(6), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "sta_mac_len_7",                   1, { { 1, 4, { CMD(4), VAP(5,3), MAC(7), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "sta_mac_len_100",                 1, { { 1, 4, { CMD(4), VAP(5,3), MAC(100), RAW(20) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "raw_len_1000_beyond_datagram",    1, { { 1, 4, { CMD(4), VAP(5,3), MAC(6), RAW(1000) }, 0, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ "datagram_1024_of_filler_tlvs",    1, { { 1, 0, {}, 1024, 0 } }, 0, 0, 0, 0, 0, 0, 1 },
	{ NULL }
};

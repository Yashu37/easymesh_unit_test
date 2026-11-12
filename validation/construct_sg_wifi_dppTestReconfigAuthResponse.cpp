/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppTestReconfigAuthResponse
 *
 * wifi_dppTestReconfigAuthResponse(apIndex, sta).  Inputs crossed: apIndex 0 / 3 / 15 / 100 / 99999999 / 0x80000000 / 0xFFFFFFFF; sta NULL / an exactly sized 6-byte heap block (zeros, broadcast, distinct bytes); socket()
 * failing; sendto() failing; one call or two consecutive calls.  Expected (CORRECT behaviour): socket failure -> RETURN_ERR, nothing sent, no close; NULL sta -> RETURN_ERR without reading it (nothing
 * sent); otherwise exactly one UDP datagram (AF_INET, 127.0.0.1:8888) of 701 bytes: the 8-byte signature, the command TLV (type 0, length 4, reconfig auth response command), the vap-name TLV (type 1, length 16, text
 * "ath<apIndex>" as an unsigned decimal, NUL terminated), the station mac TLV (type 2, length 6, the 6 bytes of sta) and the raw TLV (type 4, length 651, the canned reconfiguration authentication response frame); the socket is
 * closed exactly once; sendto failure -> RETURN_ERR (socket still closed), otherwise RETURN_OK.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wtt.h"

/* name, ap, sta_null, sta_pattern, socket_fail, send_fail, calls, last */
hwr_wtt_case_t sg_wifi_dppTestReconfigAuthResponse_suite[] = {
	{ "ap0_zero_mac",                  0, 0, 0, 0, 0, 1, 0 },
	{ "ap3_distinct_mac",              3, 0, 2, 0, 0, 1, 0 },
	{ "ap15_broadcast_mac",            15, 0, 1, 0, 0, 1, 0 },
	{ "ap100",                         100, 0, 2, 0, 0, 1, 0 },
	{ "ap_99999999",                   99999999, 0, 2, 0, 0, 1, 0 },
	{ "two_calls_ap5_ap6",             5, 0, 2, 0, 0, 2, 0 },
	{ "socket_fails",                  3, 0, 2, 1, 0, 1, 0 },
	{ "sendto_fails",                  3, 0, 2, 0, 1, 1, 0 },
	{ "socket_fails_twice",            3, 0, 2, 1, 0, 2, 0 },
	{ "sendto_fails_twice",            3, 0, 2, 0, 1, 2, 0 },
	{ "ap_above_int_max_0x80000000",   0x80000000u, 0, 2, 0, 0, 1, 0 },
	{ "ap_uint_max",                   0xFFFFFFFFu, 0, 2, 0, 0, 1, 0 },
	{ "sta_null",                      3, 1, 0, 0, 0, 1, 1 },
	{ "sta_null_ap0",                  0, 1, 0, 0, 0, 1, 1 },
	{ NULL }
};

/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_sendDataFrame
 *
 * wifi_hal_sendDataFrame(vap_id, dmac, data_buff, data_len, insert_llc, protocol, priority).  Inputs crossed: vap_id 0 / 5 / MAX_VAP-1 (valid) and -1 / MAX_VAP / MAX_VAP+5 / INT_MIN (outside the three
 * MAX_VAP-entry arrays); data_len 0 / 1 / 100 / 1500 / 1586 (the largest frame that fits: 14 + 1586 = 1600) / 1587 / 1600 / INT_MAX / INT_MIN and the negatives -1 / -13 / -14 / -15 / -100; dmac NULL; data_buff NULL
 * (with data_len 10 and 0); protocol 0x88b5 / 0 / 0x1ffff / -1 (the ether type is the low 16 bits); socket already open (cached) / not; socket() failing; no interface for the vap_id; bind() failing; sendto()
 * returning the length / -1 / length - 1.  dmac (6 bytes) and data_buff (data_len bytes) are exact heap blocks.  Expected (CORRECT behaviour): a data_len outside 0..1586, a vap_id outside 0..MAX_VAP-1, a NULL dmac
 * or a NULL data_buff with data_len > 0 -> -1 before anything is touched (no socket call); socket failure / no interface / bind failure -> -1 (the opened socket closed, g_fd_arr[vap_id] = -1); otherwise
 * one frame sent: dmac, the VAP's source MAC, ether type = htons(low 16 bits of protocol), the data, length 14 + data_len, sockaddr_ll with the interface index, halen 6 and dmac; result 0 only when sendto
 * returned the full length.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wdf.h"
#include <limits.h>
#define MAXV (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)

/* name, vap_id, no_iface, cached, sock_fail, bind_fail, dmac_null, data_null, data_len, protocol, sendto_mode, last */
hwr_wdf_case_t sg_wifi_hal_sendDataFrame_suite[] = {
	/* ---- data_len limits ---- */
	{ "data_len_0",                0, 0,0, 0,0, 0,0,    0, 0x88b5, 0, 0 },
	{ "data_len_1",                0, 0,0, 0,0, 0,0,    1, 0x88b5, 0, 0 },
	{ "data_len_100",              5, 0,0, 0,0, 0,0,  100, 0x88b5, 0, 0 },
	{ "data_len_1500",             5, 0,0, 0,0, 0,0, 1500, 0x0800, 0, 0 },
	{ "data_len_1586_largest_fit", 5, 0,0, 0,0, 0,0, 1586, 0x88b5, 0, 0 },
	{ "data_len_1587",             5, 0,0, 0,0, 0,0, 1587, 0x88b5, 0, 0 },
	{ "data_len_1600",             5, 0,0, 0,0, 0,0, 1600, 0x88b5, 0, 0 },
	{ "data_len_int_max",          5, 0,0, 0,0, 0,0, INT_MAX, 0x88b5, 0, 0 },
	{ "data_len_int_min",          5, 0,0, 0,0, 0,0, INT_MIN, 0x88b5, 0, 0 },
	{ "data_len_minus_15",         5, 0,0, 0,0, 0,0,  -15, 0x88b5, 0, 0 },
	{ "data_len_minus_100",        5, 0,0, 0,0, 0,0, -100, 0x88b5, 0, 0 },
	/* ---- socket / interface / bind / sendto ---- */
	{ "fresh_socket",              5, 0,0, 0,0, 0,0,   50, 0x88b5, 0, 0 },
	{ "cached_socket",             5, 0,1, 0,0, 0,0,   50, 0x88b5, 0, 0 },
	{ "socket_fails",              5, 0,0, 1,0, 0,0,   50, 0x88b5, 0, 0 },
	{ "no_interface",              5, 1,0, 0,0, 0,0,   50, 0x88b5, 0, 0 },
	{ "bind_fails",                5, 0,0, 0,1, 0,0,   50, 0x88b5, 0, 0 },
	{ "sendto_fails",              5, 0,0, 0,0, 0,0,   50, 0x88b5, 1, 0 },
	{ "sendto_short",              5, 0,1, 0,0, 0,0,   50, 0x88b5, 2, 0 },
	/* ---- vap_id / protocol ---- */
	{ "vap_id_0",                  0, 0,0, 0,0, 0,0,   20, 0x88b5, 0, 0 },
	{ "vap_id_max_minus_1",     MAXV - 1, 0,0, 0,0, 0,0, 20, 0x88b5, 0, 0 },
	{ "protocol_0",                5, 0,0, 0,0, 0,0,   20,      0, 0, 0 },
	{ "protocol_above_16_bits",    5, 0,0, 0,0, 0,0,   20, 0x1ffff, 0, 0 },
	{ "protocol_minus_1",          5, 0,1, 0,0, 0,0,   20,     -1, 0, 0 },
	{ "data_null_len_0",           5, 0,0, 0,0, 0,1,    0, 0x88b5, 0, 0 },
	/* ---- the original lets a data_len in -14..-1 through the length check, indexes the arrays unchecked and dereferences NULL pointers ---- */
	{ "data_len_minus_1",          5, 0,0, 0,0, 0,0,   -1, 0x88b5, 0, 1 },
	{ "data_len_minus_13",         5, 0,0, 0,0, 0,0,  -13, 0x88b5, 0, 1 },
	{ "data_len_minus_14",         5, 0,0, 0,0, 0,0,  -14, 0x88b5, 0, 1 },
	{ "vap_id_max",             MAXV, 0,0, 0,0, 0,0,   20, 0x88b5, 0, 1 },
	{ "vap_id_max_plus_5",   MAXV + 5, 0,0, 0,0, 0,0,   20, 0x88b5, 0, 1 },
	{ "vap_id_minus_1",           -1, 0,0, 0,0, 0,0,   20, 0x88b5, 0, 1 },
	{ "vap_id_int_min",      INT_MIN, 0,0, 0,0, 0,0,   20, 0x88b5, 0, 1 },
	{ "dmac_null",                 5, 0,0, 0,0, 1,0,   20, 0x88b5, 0, 1 },
	{ "data_buff_null_len_10",     5, 0,0, 0,0, 0,1,   10, 0x88b5, 0, 1 },
	{ NULL, 0, 0,0, 0,0, 0,0, 0, 0, 0, 0 }
};

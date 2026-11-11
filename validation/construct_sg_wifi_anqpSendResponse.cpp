/*
 * UNIT TEST (input constructor): construct_sg_wifi_anqpSendResponse
 *
 * wifi_anqpSendResponse(apIndex, sta, token, head).  Inputs crossed: head NULL / a list of 1-4 nodes whose elements are ANQP (len 0 / 1 / 10 / 4000 / 8175 / 8176), HS2 (len 0 / 1 / 10 / 8169 / 8170), a
 * type that is neither, with data NULL or not, a node whose element pointer is NULL; sta NULL / valid; token 0 / 0x7f / 0xff; apIndex 0 / 3 / 14 / 15; GAS configuration (advertisement id / query response
 * length limit); malloc failing for the first / second element copy.  Expected (CORRECT behaviour): head NULL -> RETURN_ERR, nothing sent; otherwise the function consumes the whole list (every node, element
 * and data block freed exactly once, also when the response is too large or a copy fails), serialises ANQP elements as { id, len, data } and HS2 elements as { 56797, len + 6, 0x50 6f 9a, type 0x11, subtype,
 * reserved 0, payload } in list order (elements with no data / len 0 / unknown type add nothing), and a total above 8179 bytes -> RETURN_ERR, nothing sent; otherwise one frame is sent for the given ap /
 * sta with category 4, action 0x0b, the token, comeback delay 0, protocol element 0x6c 0x02 (limit, id from the GAS configuration), status success (or protocol-not-supported when nothing was serialised)
 * and rsp_len equal to the bytes serialised - the frame is exactly 13 + rsp_len bytes and the function returns RETURN_OK.  After a failed copy the frame must not announce more bytes than were serialised.
 * Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wsr.h"

#define A(len)  { 0, 257, len, 0, 0 }
#define H(len)  { 1, 8,   len, 0, 0 }
/* name, head_null, n, { {type, id, len, data_null, null_elem} ... }, sta_null, token, ap, malloc_fail_at, gas_adv, gas_lim, last */
hwr_wsr_case_t sg_wifi_anqpSendResponse_suite[] = {
	{ "head_null",                       1, 0, {}, 0, 5, 1, 0, 0, 0x7f, 0 },
	{ "head_null_sta_null",              1, 0, {}, 1, 5, 1, 0, 0, 0x7f, 0 },
	{ "anqp_len_10",                     0, 1, { A(10) }, 0, 0x11, 1, 0, 0, 0x7f, 0 },
	{ "anqp_len_1",                      0, 1, { A(1) }, 0, 0x11, 1, 0, 0, 0x7f, 0 },
	{ "anqp_len_0_skipped",              0, 1, { A(0) }, 0, 0x11, 1, 0, 0, 0x7f, 0 },
	{ "anqp_data_null_skipped",          0, 1, { { 0, 257, 10, 1, 0 } }, 0, 0x11, 1, 0, 0, 0x7f, 0 },
	{ "hs2_len_10",                      0, 1, { H(10) }, 0, 0x22, 1, 0, 0, 0x7f, 0 },
	{ "hs2_len_1",                       0, 1, { H(1) }, 0, 0x22, 1, 0, 0, 0x7f, 0 },
	{ "hs2_len_0_skipped",               0, 1, { H(0) }, 0, 0x22, 1, 0, 0, 0x7f, 0 },
	{ "hs2_data_null_skipped",           0, 1, { { 1, 8, 10, 1, 0 } }, 0, 0x22, 1, 0, 0, 0x7f, 0 },
	{ "unknown_type_element_freed",      0, 1, { { 2, 1, 10, 0, 0 } }, 0, 0x33, 1, 0, 0, 0x7f, 0 },
	{ "null_element_node_then_anqp",     0, 2, { { 0, 0, 0, 0, 1 }, A(10) }, 0, 0x33, 1, 0, 0, 0x7f, 0 },
	{ "two_anqp",                        0, 2, { A(10), A(20) }, 0, 0x44, 1, 0, 0, 0x7f, 0 },
	{ "anqp_then_hs2",                   0, 2, { A(10), H(20) }, 0, 0x44, 1, 0, 0, 0x7f, 0 },
	{ "hs2_then_anqp",                   0, 2, { H(20), A(10) }, 0, 0x44, 1, 0, 0, 0x7f, 0 },
	{ "four_mixed_elements",             0, 4, { A(5), H(6), { 2, 0, 3, 0, 0 }, A(7) }, 0, 0x44, 2, 0, 0, 0x7f, 0 },
	{ "sta_null",                        0, 1, { A(10) }, 1, 0x55, 1, 0, 0, 0x7f, 0 },
	{ "token_0xff_ap_15",                0, 1, { A(10) }, 0, 0xff, 15, 0, 0, 0x7f, 0 },
	{ "token_0_ap_0",                    0, 1, { H(10) }, 0, 0, 0, 0, 0, 0x7f, 0 },
	{ "gas_config_other_values",         0, 1, { A(10) }, 0, 0x66, 14, 0, 1, 0x33, 0 },
	{ "anqp_exact_limit_8175",           0, 1, { A(8175) }, 0, 0x77, 1, 0, 0, 0x7f, 0 },
	{ "anqp_one_over_8176",              0, 1, { A(8176) }, 0, 0x77, 1, 0, 0, 0x7f, 0 },
	{ "hs2_exact_limit_8169",            0, 1, { H(8169) }, 0, 0x77, 1, 0, 0, 0x7f, 0 },
	{ "hs2_one_over_8170",               0, 1, { H(8170) }, 0, 0x77, 1, 0, 0, 0x7f, 0 },
	{ "two_elements_exact_total_8179",   0, 2, { A(4000), H(4165) }, 0, 0x88, 1, 0, 0, 0x7f, 0 },
	{ "second_element_exceeds_total",    0, 2, { A(4000), A(4180) }, 0, 0x88, 1, 0, 0, 0x7f, 0 },
	{ "overflow_frees_remaining_nodes",  0, 4, { A(100), A(8100), A(50), H(60) }, 0, 0x88, 1, 0, 0, 0x7f, 0 },
	{ "malloc_fails_first_element",      0, 2, { A(10), A(20) }, 0, 0x99, 1, 1, 0, 0x7f, 0 },
	{ "malloc_fails_second_element",     0, 3, { A(10), A(20), A(30) }, 0, 0x99, 1, 2, 0, 0x7f, 0 },
	{ "malloc_fails_hs2_element",        0, 2, { A(10), H(20) }, 0, 0x99, 1, 2, 0, 0x7f, 0 },
	{ NULL }
};

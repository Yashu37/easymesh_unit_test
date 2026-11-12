/*
 * UNIT TEST (input constructor): construct_sg_wifi_send_test_frame
 *
 * wifi_send_test_frame(frame, frame_len, arg, cmd, dir) wraps a captured 802.11 frame into one test datagram and sends it by UDP to 127.0.0.1:8888: 8-byte signature, command TLV (type 0, length 4), vap-name
 * TLV (type 1, length 16, the first 16 bytes of arg->interface_name), station-mac TLV (type 2, length 6, arg->mac), direction TLV (type 3, length 1) and raw-frame TLV (type 4, length frame_len), all built
 * with set_tlv in a local msg[2048].  Inputs crossed: frame_len (0, 1, 26, 64, 100, 200, 255, 256, 1000, 1992, 1993 = the largest that fits, 1994, 2048, 4000, 65535, 65536), NULL frame, NULL arg,
 * command (probe_req / 8021x / action / deauth), direction (uplink / downlink), interface-name length (empty / 15 / 31 characters), station mac (zeros / broadcast / distinct bytes), socket failure and sendto
 * failure.  The frame is an exactly sized heap block and arg an exactly sized heap block.
 * Expected (CORRECT behaviour): for valid input RETURN_OK and exactly one datagram to 127.0.0.1:8888 of 8 + 8 + 20 + 10 + 5 + 4 + frame_len bytes (the five TLVs back to back, nothing after the raw
 * frame), the socket closed once; socket failure -> RETURN_ERR without close; sendto failure -> RETURN_ERR after closing; a NULL arg, a NULL frame with frame_len > 0 or a frame_len that does not fit
 * msg[2048] (more than 1993) -> RETURN_ERR without sending and without writing outside msg.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wft.h"

/* name, flen, frame_null, arg_null, cmd, dir, name, mac, socket_fail, send_fail, last */
hwr_wft_case_t sg_wifi_send_test_frame_suite[] = {
	{ "success_probe_req_uplink",                100, 0, 0, 0, 0, 0, 2, 0, 0, 0 },
	{ "success_8021x_downlink",                  64, 0, 0, 1, 1, 0, 2, 0, 0, 0 },
	{ "success_action",                          200, 0, 0, 2, 0, 0, 2, 0, 0, 0 },
	{ "success_deauth_26_bytes",                 26, 0, 0, 3, 1, 0, 1, 0, 0, 0 },
	{ "frame_len_0",                             0, 0, 0, 0, 0, 0, 2, 0, 0, 0 },
	{ "frame_len_1",                             1, 0, 0, 0, 0, 0, 2, 0, 0, 0 },
	{ "frame_len_255",                           255, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "frame_len_256",                           256, 0, 0, 1, 0, 0, 2, 0, 0, 0 },
	{ "frame_len_1000",                          1000, 0, 0, 2, 1, 0, 2, 0, 0, 0 },
	{ "frame_len_1992",                          1992, 0, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_len_1993_largest_that_fits",        1993, 0, 0, 0, 1, 0, 2, 0, 0, 1 },
	{ "name_empty",                              100, 0, 0, 0, 0, 1, 2, 0, 0, 0 },
	{ "name_15_chars",                           100, 0, 0, 1, 0, 2, 2, 0, 0, 0 },
	{ "name_31_chars",                           100, 0, 0, 2, 0, 3, 2, 0, 0, 0 },
	{ "mac_zeros",                               100, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mac_broadcast",                           100, 0, 0, 3, 1, 0, 1, 0, 0, 0 },
	{ "socket_fails",                            100, 0, 0, 0, 0, 0, 2, 1, 0, 0 },
	{ "socket_fails_frame_len_0",                0, 0, 0, 0, 0, 0, 2, 1, 0, 0 },
	{ "sendto_fails_closes_socket",              100, 0, 0, 0, 0, 0, 2, 0, 1, 0 },
	{ "sendto_fails_frame_len_1993",             1993, 0, 0, 1, 0, 0, 2, 0, 1, 1 },
	{ "arg_null",                                100, 0, 1, 0, 0, 0, 2, 0, 0, 1 },
	{ "arg_null_frame_len_0",                    0, 0, 1, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_null_len_100",                      100, 1, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_null_len_1",                        1, 1, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_len_1994_overflows_msg",            1994, 0, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_len_2048",                          2048, 0, 0, 1, 0, 0, 2, 0, 0, 1 },
	{ "frame_len_4000",                          4000, 0, 0, 2, 1, 0, 2, 0, 0, 1 },
	{ "frame_len_65535",                         65535, 0, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ "frame_len_65536_length_wraps",            65536, 0, 0, 0, 0, 0, 2, 0, 0, 1 },
	{ NULL }
};

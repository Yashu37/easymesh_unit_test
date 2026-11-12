/*
 * UNIT TEST (input constructor): construct_sg_callback_dpp_config_req_frame_received
 *
 * callback_dpp_config_req_frame_received(ap_index, sta, token, attrib, len): forwards the received DPP Configuration Request to the registered dpp_config_req_callback.  Inputs crossed: callback
 * registered or not, the other four DPP callbacks registered (marker callbacks that must NOT be called) or NULL, ap index (0, 1, 15, negative), token (0, 1, 255), attribute buffer (NULL, empty,
 * 1 byte, 64 bytes, 1024 bytes: a heap block of exactly the declared length), a declared length different from the buffer (the function only forwards it), station mac (zeros, pattern, 0xFF) and one
 * or two consecutive calls.
 * Expected (CORRECT behaviour): a registered callback is called exactly once per call with exactly the arguments received (ap index, mac contents, token, the SAME attrib pointer, the length), the
 * attribute buffer is not read or modified by the forwarder, the other callbacks are not called and the table is not modified; with NO callback registered (NULL: the HAL registers it with
 * wifi_dpp_frame_received_callbacks_register, which accepts NULL to clear a slot) the frame is dropped silently instead of calling through a NULL pointer.  Rows with last = 1 break the original: they
 * run LAST.
 */
#include "hwr_wcf.h"

/* name, registered, others, ap_index, token, attrlen, len_extra, sta, calls, last */
hwr_wcf_case_t sg_callback_dpp_config_req_frame_received_suite[] = {
	{ "forward_basic",                   1, 0, 1, 7, 64, 0, 1, 1, 0 },
	{ "forward_ap_index_0",              1, 0, 0, 7, 64, 0, 1, 1, 0 },
	{ "forward_ap_index_15",             1, 0, 15, 7, 64, 0, 1, 1, 0 },
	{ "forward_ap_index_negative",       1, 0, -1, 7, 64, 0, 1, 1, 0 },
	{ "forward_token_0",                 1, 0, 1, 0, 64, 0, 1, 1, 0 },
	{ "forward_token_255",               1, 0, 1, 255, 64, 0, 1, 1, 0 },
	{ "forward_attrib_null",             1, 0, 1, 7, -1, 0, 1, 1, 0 },
	{ "forward_attrib_empty",            1, 0, 1, 7, 0, 0, 1, 1, 0 },
	{ "forward_attrib_1_byte",           1, 0, 1, 7, 1, 0, 1, 1, 0 },
	{ "forward_attrib_1024_bytes",       1, 0, 1, 7, 1024, 0, 1, 1, 0 },
	{ "forward_length_larger_than_buffer", 1, 0, 1, 7, 8, 1000, 1, 1, 0 },
	{ "forward_sta_zero",                1, 0, 1, 7, 64, 0, 0, 1, 0 },
	{ "forward_sta_ff",                  1, 0, 1, 7, 64, 0, 2, 1, 0 },
	{ "forward_other_callbacks_set",     1, 1, 1, 7, 64, 0, 1, 1, 0 },
	{ "forward_two_calls",               1, 0, 1, 7, 64, 0, 1, 2, 0 },
	{ "forward_two_calls_others_set",    1, 1, 3, 9, 16, 0, 1, 2, 0 },
	/* inputs that crash the original: run LAST */
	{ "callback_not_registered",         0, 0, 1, 7, 64, 0, 1, 1, 1 },
	{ "callback_not_registered_others_set", 0, 1, 1, 7, 64, 0, 1, 1, 1 },
	{ "callback_not_registered_attrib_null", 0, 0, 1, 7, -1, 0, 1, 1, 1 },
	{ "callback_not_registered_two_calls", 0, 0, 1, 7, 64, 0, 1, 2, 1 },
	{ NULL }
};

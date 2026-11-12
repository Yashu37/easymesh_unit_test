/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppProcessConfigResult
 *
 * wifi_dppProcessConfigResult(dpp_ctx): the received frame (dpp_ctx->received_frame.frame / .length) is a DPP Configuration Result: a 6-byte action frame body followed by a wrapped data attribute that
 * holds, AES-SIV encrypted with the session key instance->ke (AAD = the 6-byte body), the DPP status attribute (1 byte, 0 = success) and the enrollee nonce.  The runner builds REAL frames in heap blocks
 * of exactly the declared length and encrypts them with the key the function uses (SIV_256 / 384 / 512 by instance->digestlen), so the success path really runs.
 * Inputs crossed: NULL context / session instance / frame pointer, declared frame length (natural, 0, 5, 6, 7, 9), digestlen 32 / 48 / 64 and an unsupported 20, 0..2 attributes in front of the wrapped
 * data, the wrapped data absent / valid / corrupted / shorter than the SIV tag / length field larger than the frame / empty plaintext / plaintext of exactly 128 bytes (the size of plain[]) and 129 /
 * encrypted with another key, the inner status attribute absent / 0 / 1 / 0xFF / 2 bytes long / empty, the inner enrollee nonce absent / matching / different and in front of or behind the status.
 * Expected (CORRECT behaviour): RETURN_OK and enrollee_status = RESPONDER_STATUS_OK only for a complete valid frame whose status is 0 and whose enrollee nonce equals instance->enrollee_nonce (DPP
 * Configuration Result carries E-nonce so that an old result cannot be replayed); every other input -> RETURN_ERR and enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE without reading outside the
 * frame; a NULL context -> RETURN_ERR.  The instance's k1 / k2 / rauth / iauth / nonces other than the enrollee nonce, the context's config / channels_list / session union / sta_mac are not touched
 * (poisoned in the runner).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wcr.h"

/* name, nul, flen, digest, before, wrap, status, enonce, enonce_first, last */
hwr_wcr_case_t sg_wifi_dppProcessConfigResult_suite[] = {
	{ "success_sha256",                    0, -1, 32, 0, 1, 1, 1, 0, 0 },
	{ "success_sha384",                    0, -1, 48, 0, 1, 1, 1, 0, 0 },
	{ "success_sha512",                    0, -1, 64, 0, 1, 1, 1, 0, 0 },
	{ "success_one_attribute_before",      0, -1, 32, 1, 1, 1, 1, 0, 0 },
	{ "success_two_attributes_before",     0, -1, 32, 2, 1, 1, 1, 0, 0 },
	{ "success_enonce_first",              0, -1, 32, 0, 1, 1, 1, 1, 0 },
	{ "success_plaintext_128_bytes",       0, -1, 32, 0, 6, 1, 1, 0, 0 },
	{ "status_value_1",                    0, -1, 32, 0, 1, 2, 1, 0, 0 },
	{ "status_value_ff",                   0, -1, 32, 0, 1, 3, 1, 0, 0 },
	{ "status_absent",                     0, -1, 32, 0, 1, 0, 1, 0, 0 },
	{ "status_length_2",                   0, -1, 32, 0, 1, 4, 1, 0, 0 },
	{ "status_length_0",                   0, -1, 32, 0, 1, 5, 1, 0, 0 },
	{ "wrapped_data_absent",               0, -1, 32, 0, 0, 1, 1, 0, 0 },
	{ "wrapped_data_corrupted",            0, -1, 32, 0, 2, 1, 1, 0, 0 },
	{ "wrapped_data_length_8",             0, -1, 32, 0, 3, 1, 1, 0, 0 },
	{ "wrapped_data_length_beyond_frame",  0, -1, 32, 0, 4, 1, 1, 0, 0 },
	{ "wrapped_data_empty_plaintext",      0, -1, 32, 0, 5, 1, 1, 0, 0 },
	{ "wrapped_data_plaintext_129_bytes",  0, -1, 32, 0, 7, 1, 1, 0, 0 },
	{ "wrapped_data_wrong_key",            0, -1, 32, 0, 8, 1, 1, 0, 0 },
	{ "digestlen_20_unsupported",          0, -1, 20, 0, 1, 1, 1, 0, 0 },
	{ "frame_length_6_header_only",        0,  6, 32, 0, 1, 1, 1, 0, 0 },
	{ "frame_length_7_truncated_header",   0,  7, 32, 0, 1, 1, 1, 0, 0 },
	{ "frame_length_9_truncated_length",   0,  9, 32, 0, 1, 1, 1, 0, 0 },
	/* the enrollee nonce is never checked by the original (accepted for any value / absent) */
	{ "enrollee_nonce_absent",             0, -1, 32, 0, 1, 1, 0, 0, 0 },
	{ "enrollee_nonce_mismatch",           0, -1, 32, 0, 1, 1, 2, 0, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                          1, -1, 32, 0, 1, 1, 1, 0, 1 },
	{ "session_instance_null",             2, -1, 32, 0, 1, 1, 1, 0, 1 },
	{ "frame_pointer_null",                3, -1, 32, 0, 1, 1, 1, 0, 1 },
	{ "frame_length_0",                    0,  0, 32, 0, 1, 1, 1, 0, 1 },
	{ "frame_length_5",                    0,  5, 32, 0, 1, 1, 1, 0, 1 },
	{ NULL }
};

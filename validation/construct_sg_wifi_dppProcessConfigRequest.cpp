/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppProcessConfigRequest
 *
 * wifi_dppProcessConfigRequest(ctx): ctx->received_frame.frame points at the attributes of a received DPP Configuration Request (the GAS payload; .length is the attribute length) which hold a wrapped
 * data attribute: the enrollee nonce (and the configuration attributes object) AES-SIV encrypted, without associated data, with the session key instance->ke (SIV_256 / 384 / 512 by instance->digestlen).
 * The function decrypts it into buff[1024], finds the enrollee nonce, copies it into instance->enrollee_nonce (32 bytes) and sets ctx->enrollee_status.  The runner builds REAL frames in heap blocks of
 * exactly the declared length and encrypts them with the key the function uses, so the success path really runs.
 * Inputs crossed: NULL context / session instance / frame pointer, declared frame length (natural, 0, 3, 6), digestlen 32 / 48 / 64 and an unsupported 20, 0..2 attributes in front of the wrapped data,
 * the wrapped data absent / valid / corrupted / shorter than the SIV tag / length field larger than the frame / empty plaintext / plaintext of exactly 1024 bytes (the size of buff[]) and 1025 / encrypted
 * with another key, the enrollee nonce absent or 16 / 33 / 8 / 0 / 32 bytes long, 0..2 other attributes in front of it in the plaintext and a configuration attributes object behind it.
 * Expected (CORRECT behaviour): RETURN_OK, RESPONDER_STATUS_OK and the nonce stored in instance->enrollee_nonce only for a complete valid frame whose enrollee nonce is exactly noncelen = 16 bytes long (the
 * function's own message prints "enrollee nonce length mismatch %u/%u" with noncelen); every other input -> RETURN_ERR, RESPONDER_STATUS_AUTH_FAILURE (the status the original uses for every failure),
 * instance->enrollee_nonce unchanged and no read outside the frame; a NULL context -> RETURN_ERR.  The instance's k1 / k2 / rauth / iauth / responder_nonce / initiator_nonce and the context's config /
 * channels_list / session union / sta_mac are not touched (poisoned in the runner).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wcq.h"

/* name, nul, flen, digest, before, wrap, nonce, inner_before, config_obj, last */
hwr_wcq_case_t sg_wifi_dppProcessConfigRequest_suite[] = {
	{ "success_sha256",                    0, -1, 32, 0, 1, 1, 0, 0, 0 },
	{ "success_sha384",                    0, -1, 48, 0, 1, 1, 0, 0, 0 },
	{ "success_sha512",                    0, -1, 64, 0, 1, 1, 0, 0, 0 },
	{ "success_one_attribute_before",      0, -1, 32, 1, 1, 1, 0, 0, 0 },
	{ "success_two_attributes_before",     0, -1, 32, 2, 1, 1, 0, 0, 0 },
	{ "success_inner_attribute_before",    0, -1, 32, 0, 1, 1, 1, 0, 0 },
	{ "success_two_inner_attributes",      0, -1, 32, 0, 1, 1, 2, 0, 0 },
	{ "success_with_config_object",        0, -1, 32, 0, 1, 1, 0, 1, 0 },
	{ "success_plaintext_1024_bytes",      0, -1, 32, 0, 6, 1, 0, 0, 0 },
	{ "wrapped_plaintext_1025_bytes",      0, -1, 32, 0, 7, 1, 0, 0, 0 },
	{ "wrapped_data_absent",               0, -1, 32, 0, 0, 1, 0, 0, 0 },
	{ "wrapped_data_corrupted",            0, -1, 32, 0, 2, 1, 0, 0, 0 },
	{ "wrapped_data_length_8",             0, -1, 32, 0, 3, 1, 0, 0, 0 },
	{ "wrapped_data_length_beyond_frame",  0, -1, 32, 0, 4, 1, 0, 0, 0 },
	{ "wrapped_data_empty_plaintext",      0, -1, 32, 0, 5, 1, 0, 0, 0 },
	{ "wrapped_data_wrong_key",            0, -1, 32, 0, 8, 1, 0, 0, 0 },
	{ "digestlen_20_unsupported",          0, -1, 20, 0, 1, 1, 0, 0, 0 },
	{ "nonce_absent",                      0, -1, 32, 0, 1, 0, 0, 0, 0 },
	{ "nonce_length_33",                   0, -1, 32, 0, 1, 2, 0, 0, 0 },
	{ "frame_length_0",                    0,  0, 32, 0, 1, 1, 0, 0, 0 },
	{ "frame_length_3",                    0,  3, 32, 0, 1, 1, 0, 0, 0 },
	{ "frame_length_6_truncated_value",    0,  6, 32, 0, 1, 1, 0, 0, 0 },
	/* nonce length != noncelen (16): accepted by the original (only > 32 is rejected) */
	{ "nonce_length_8",                    0, -1, 32, 0, 1, 3, 0, 0, 0 },
	{ "nonce_length_0",                    0, -1, 32, 0, 1, 4, 0, 0, 0 },
	{ "nonce_length_32",                   0, -1, 32, 0, 1, 5, 0, 0, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                          1, -1, 32, 0, 1, 1, 0, 0, 1 },
	{ "session_instance_null",             2, -1, 32, 0, 1, 1, 0, 0, 1 },
	{ "frame_pointer_null",                3, -1, 32, 0, 1, 1, 0, 0, 1 },
	{ NULL }
};

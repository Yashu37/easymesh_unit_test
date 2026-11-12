/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppProcessReconfigAuthResponse
 *
 * wifi_dppProcessReconfigAuthResponse(dpp_ctx): the received frame (dpp_ctx->received_frame.frame / .length) is a DPP Reconfiguration Authentication Response made of attributes (transaction id,
 * protocol version, connector, responder protocol key, wrapped data = AES-SIV encrypted responder nonce / capabilities / initiator nonce).  The runner builds REAL frames: a P-256 reconfig key, a responder
 * protocol key point, a connector JSON with a netAccessKey point and a wrapped-data attribute encrypted with the key the function derives (HKDF over M = priv * (P + C)), so the success path really runs.
 * Inputs crossed: context state (NULL context / reconfigCtx / instance / instance->x / instance->y / frame pointer), declared frame length (natural, header only, shorter than the header, truncated
 * attribute headers), dpp_init_retries and which tran_id table entry matches, every attribute absent / wrong length / malformed, connector variants (no '.', bad base64, not json, missing netAccessKey /
 * x / y, 1024 characters, x or y longer than the decode buffers, x not a string, TLV length larger than the frame), responder key variants (absent, 32 bytes, off the curve), wrapped data variants (absent,
 * corrupted, shorter than the SIV tag, length larger than the frame, empty) and the inner nonces (absent, wrong length, mismatching initiator nonce).
 * Expected (CORRECT behaviour): RETURN_OK only for a complete valid frame (version stored, matching transaction id stored, responder nonce copied, enrollee_status untouched); every malformed frame ->
 * RETURN_ERR without reading outside the frame or the decode buffers; key / decrypt / nonce failures also set enrollee_status = RESPONDER_STATUS_AUTH_FAILURE (the nonces must be exactly
 * noncelen = 16 bytes long: the function's own message prints "nonce length mismatch %u/%u" with noncelen); a NULL context or NULL reconfigCtx is rejected with RETURN_ERR.  Rows with last = 1 break
 * the original: they run LAST.  Not modelled: a responder key TLV shorter than 2 * primelen that is the LAST attribute makes BN_bin2bn read past the frame, but the read happens inside libcrypto
 * (not instrumented by ASan), so it cannot be shown here.
 */
#include "hwr_wra.h"

/* name, nul, flen, retries, tran, ver, conn, key, wrap, rn, rcap, in, last */
hwr_wra_case_t sg_wifi_dppProcessReconfigAuthResponse_suite[] = {
	{ "success_basic",                       0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "success_with_responder_cap",          0, -1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "success_retries3_match_newest",       0, -1, 3, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "success_retries3_match_oldest",       0, -1, 3, 5, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "instance_null",                       3, -1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "header_only_frame",                   0,  6, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "tran_absent",                         0, -1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "tran_length_2",                       0, -1, 0, 3, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "tran_mismatch",                       0, -1, 0, 2, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "ver_absent",                          0, -1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0 },
	{ "conn_absent",                         0, -1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0 },
	{ "conn_no_dot",                         0, -1, 0, 1, 1, 2, 1, 1, 1, 0, 1, 0 },
	{ "conn_bad_base64_body",                0, -1, 0, 1, 1, 4, 1, 1, 1, 0, 1, 0 },
	{ "conn_body_not_json",                  0, -1, 0, 1, 1, 5, 1, 1, 1, 0, 1, 0 },
	{ "conn_no_netaccesskey",                0, -1, 0, 1, 1, 6, 1, 1, 1, 0, 1, 0 },
	{ "conn_no_x",                           0, -1, 0, 1, 1, 7, 1, 1, 1, 0, 1, 0 },
	{ "conn_no_y",                           0, -1, 0, 1, 1, 8, 1, 1, 1, 0, 1, 0 },
	{ "conn_x_bad_base64",                   0, -1, 0, 1, 1, 9, 1, 1, 1, 0, 1, 0 },
	{ "conn_length_1024",                    0, -1, 0, 1, 1, 10, 1, 1, 1, 0, 1, 0 },
	{ "key_absent",                          0, -1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0 },
	{ "key_32_bytes_wrap_present",           0, -1, 0, 1, 1, 1, 2, 1, 1, 0, 1, 0 },
	{ "key_off_curve",                       0, -1, 0, 1, 1, 1, 4, 1, 1, 0, 1, 0 },
	{ "wrap_absent",                         0, -1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0 },
	{ "wrap_corrupted",                      0, -1, 0, 1, 1, 1, 1, 2, 1, 0, 1, 0 },
	{ "wrap_length_8",                       0, -1, 0, 1, 1, 1, 1, 3, 1, 0, 1, 0 },
	{ "wrap_empty_plaintext",                0, -1, 0, 1, 1, 1, 1, 5, 1, 0, 1, 0 },
	{ "resp_nonce_absent",                   0, -1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0 },
	{ "resp_nonce_33_bytes",                 0, -1, 0, 1, 1, 1, 1, 1, 3, 0, 1, 0 },
	{ "init_nonce_absent",                   0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
	{ "init_nonce_mismatch",                 0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 2, 0 },
	{ "init_nonce_33_bytes",                 0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 4, 0 },
	/* nonce length != noncelen (16): accepted by the original (only > 32 is rejected) */
	{ "resp_nonce_8_bytes",                  0, -1, 0, 1, 1, 1, 1, 1, 4, 0, 1, 0 },
	{ "resp_nonce_empty",                    0, -1, 0, 1, 1, 1, 1, 1, 5, 0, 1, 0 },
	{ "resp_nonce_32_bytes",                 0, -1, 0, 1, 1, 1, 1, 1, 2, 0, 1, 0 },
	{ "init_nonce_8_bytes_prefix_match",     0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 3, 0 },
	{ "init_nonce_empty",                    0, -1, 0, 1, 1, 1, 1, 1, 1, 0, 5, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                            1, -1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "reconfig_ctx_null",                   2, -1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "frame_pointer_null",                  6, -1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "frame_length_0",                      0,  0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "frame_length_5",                      0,  5, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "frame_length_7_truncated_tlv_type",   0,  7, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "frame_length_9_truncated_tlv_length", 0,  9, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
	{ "conn_tlv_length_beyond_frame",        0, -1, 0, 1, 1, 15, 0, 0, 1, 0, 1, 1 },
	{ "conn_x_65_bytes",                     0, -1, 0, 1, 1, 12, 1, 1, 1, 0, 1, 1 },
	{ "conn_y_200_bytes",                    0, -1, 0, 1, 1, 13, 1, 1, 1, 0, 1, 1 },
	{ "conn_x_is_json_number",               0, -1, 0, 1, 1, 16, 1, 1, 1, 0, 1, 1 },
	{ "wrap_length_beyond_frame",            0, -1, 0, 1, 1, 1, 1, 4, 1, 0, 1, 1 },
	{ NULL }
};

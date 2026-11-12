/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppProcessAuthResponse
 *
 * wifi_dppProcessAuthResponse(dpp_ctx): dpp_ctx->received_frame is a DPP Authentication Response (6-byte public action frame header + attributes: protocol version, status, responder boot hash,
 * [initiator boot hash,] responder protocol key, wrapped data).  The runner builds REAL frames for a real P-256 session: the responder protocol key point PR, the keys the function derives (N = pi * PR,
 * k2 = HKDF(N.x, "second intermediate key"), ke = HKDF(m | N.x [| l], salt = I-nonce | R-nonce, "DPP Key")), the primary wrapped data (AES-SIV with k2, AAD = header + the attributes in front of it:
 * responder nonce, capabilities, initiator nonce and the secondary wrapped data) and the secondary wrapped data (AES-SIV with ke: the responder auth tag = R-auth').  rPubKey / iPubKey are base64
 * SubjectPublicKeyInfo of the bootstrap keys, so the success path really runs.
 * Inputs crossed: NULL context / session instance / instance->x / instance->y / frame pointer, declared frame length (natural, 0, 5, header only, 7), digestlen 32 / 48 / 64 and an unsupported 20, mutual
 * authentication (initiator boot hash present), every attribute absent / wrong length / wrong value, the responder protocol key (absent, 32 bytes, off the curve), the primary and secondary wrapped data
 * (absent / corrupted / shorter than the SIV tag / length field larger than the frame / empty), the inner nonces (absent, wrong length, mismatching initiator nonce), the responder auth tag (absent, wrong
 * value, wrong length) and the configured rPubKey / iPubKey (bad base64, valid base64 of garbage DER).
 * Expected (CORRECT behaviour): RETURN_OK, RESPONDER_STATUS_OK, the version / responder nonce / mutual flag / k2 / R-auth / I-auth / channel stored, only for a complete valid frame whose boot hash is the full
 * SHA-256 of the responder boot key, whose nonces are exactly noncelen = 16 bytes long, whose initiator nonce equals the one sent in the Authentication Request and whose responder auth tag equals
 * R-auth' computed by the function; every other input -> RETURN_ERR and RESPONDER_STATUS_AUTH_FAILURE (the original does not set it when the context has no session instance / x / y; either value is
 * accepted there), without reading outside the frame, the key hash buffer or the NULL objects.  The instance's k1 / enrollee_nonce / M / responder_connector pointer and the context's config /
 * channels_list / sta_mac are not touched (poisoned in the runner).  Mutual authentication: create_auth_tags hashes BR.x twice instead of BI.x (R-auth' = H(I | R | PI.x | PR.x | [BI.x |] BR.x | 0)); that
 * belongs to create_auth_tags, so the mutual case does not compare I-auth / R-auth and sends the tag the function computes.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wap.h"

/* name, nul, flen, digest, mutual, ver, status, bhash, rpub, ipub, rkey, wrap, rn, rcap, in, sec, tag, last */
hwr_wap_case_t sg_wifi_dppProcessAuthResponse_suite[] = {
	{ "success_sha256",                    0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "success_sha384",                    0, -1, 48, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "success_sha512",                    0, -1, 64, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "success_mutual",                    0, -1, 32, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "success_version_absent",            0, -1, 32, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "instance_null",                     2, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "instance_x_null",                   3, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "instance_y_null",                   4, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "header_only_frame",                 0, 6, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "status_absent",                     0, -1, 32, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "status_nonzero",                    0, -1, 32, 0, 1, 2, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "status_length_2",                   0, -1, 32, 0, 1, 3, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "boot_hash_absent",                  0, -1, 32, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "boot_hash_wrong",                   0, -1, 32, 0, 1, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "rkey_absent",                       0, -1, 32, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0 },
	{ "rkey_32_bytes",                     0, -1, 32, 0, 1, 1, 1, 0, 0, 2, 1, 1, 1, 1, 1, 1, 0 },
	{ "rkey_off_curve",                    0, -1, 32, 0, 1, 1, 1, 0, 0, 3, 1, 1, 1, 1, 1, 1, 0 },
	{ "wrap_absent",                       0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0 },
	{ "wrap_corrupted",                    0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 2, 1, 1, 1, 1, 1, 0 },
	{ "wrap_length_8",                     0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 3, 1, 1, 1, 1, 1, 0 },
	{ "wrap_empty_plaintext",              0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 5, 1, 1, 1, 1, 1, 0 },
	{ "rn_absent",                         0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0 },
	{ "rn_33_bytes",                       0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 3, 1, 1, 1, 1, 0 },
	{ "in_absent",                         0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0 },
	{ "sec_absent",                        0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0 },
	{ "sec_corrupted",                     0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 2, 1, 0 },
	{ "sec_length_8",                      0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 3, 1, 0 },
	{ "sec_empty_plaintext",               0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 5, 1, 0 },
	{ "tag_absent",                        0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0 },
	{ "digestlen_20_unsupported",          0, -1, 20, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "rpub_bad_base64",                   0, -1, 32, 0, 1, 1, 1, 3, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "ipub_bad_base64",                   0, -1, 32, 0, 1, 1, 1, 0, 3, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "frame_length_7_truncated_tlv_type", 0, 7, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	/* nonce / hash / auth tag lengths and values that the original accepts (wrong behaviour) */
	{ "resp_nonce_8_bytes",                0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 4, 1, 1, 1, 1, 0 },
	{ "resp_nonce_empty",                  0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 5, 1, 1, 1, 1, 0 },
	{ "resp_nonce_32_bytes",               0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 2, 1, 1, 1, 1, 0 },
	{ "init_nonce_mismatch",               0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 2, 1, 1, 0 },
	{ "init_nonce_8_bytes_prefix_match",   0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 3, 1, 1, 0 },
	{ "boot_hash_16_byte_prefix",          0, -1, 32, 0, 1, 1, 3, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "boot_hash_empty",                   0, -1, 32, 0, 1, 1, 4, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0 },
	{ "auth_tag_wrong_value",              0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 2, 0 },
	{ "auth_tag_length_8",                 0, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 3, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                          1, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ "frame_pointer_null",                5, -1, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ "frame_length_0",                    0, 0, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ "frame_length_5",                    0, 5, 32, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ "rpub_invalid_der",                  0, -1, 32, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ "ipub_invalid_der",                  0, -1, 32, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
	{ NULL }
};

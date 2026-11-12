/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppInitiate
 *
 * wifi_dppInitiate(ctx): starts a DPP authentication (config session).  It decodes the responder / initiator bootstrap keys (rPubKey / iPubKey, base64 SubjectPublicKeyInfo), creates the session instance
 * (create_dpp_session_instance: group of the responder key, initiator protocol key, nonce, M = B_R * p_I and m), derives k1 = HKDF(M.x, "first intermediate key"), builds the Authentication Request
 * (initiator boot hash, responder boot hash, protocol version when configurator_version > 1, initiator protocol key x || y, channel attribute of the radio's home channel, wrapped data = AES-SIV with k1 of the
 * initiator nonce and capabilities) and sends it with wifi_sendActionFrame (ap_index, sta_mac, frequency of the session channel, frame, header + attribute bytes).  The runner builds a real heap context, real
 * keys and base64 strings, captures the frame, recomputes M, k1, the boot hashes and the protocol key itself and decrypts the wrapped data.
 * Inputs crossed: NULL context, curve of the responder key (P-256 / P-384 / P-521 / secp256k1 which create_dpp_session_instance does not handle), rPubKey / iPubKey valid / invalid base64 / valid base64 of garbage
 * DER / empty, configurator_version 1 / 2, home channel and session channel (valid, 0, 200), ap index, a second wifi_dppInitiate on the same context, and an initiator protocol key whose x (or y) is shorter than
 * the prime (retried until the random key has that property).
 * Expected (CORRECT behaviour): RETURN_OK for a valid context: exactly one wifi_sendActionFrame(ap_index, sta_mac, channel_to_frequency(channel), frame, header + attributes) with the public action header
 * (category 4, action 9), the DPP OUI 50:6F:9A:1A, crypto 1, frame type auth request, I-boot hash and R-boot hash = SHA-256 of the DER of the COMPRESSED keys, the protocol version attribute (version > 1 only),
 * the initiator protocol key as x || y with each coordinate zero padded to the prime length, the channel attribute (operating class, channel) of the home channel and the wrapped data decrypting with k1 to the
 * initiator nonce; afterwards session_data.state = STATE_DPP_AUTH_RSP_PENDING and activation_status = ActStatus_In_Progress.  A NULL context, a key that cannot be decoded, a session instance that cannot be
 * created or a session channel without a frequency -> RETURN_ERR, activation_status = ActStatus_Failed (NULL context excepted), nothing sent and the state unchanged.  No EC_KEY decoded by the function is leaked.
 * The context's config object, channels_list, received_frame, dpp_init_retries, token and enrollee_version are not touched (poisoned in the runner).  Rows with last = 1 break the original: they run LAST.  Not
 * counted here: the initiator / responder bootstrap EC_KEYs of create_dpp_session_instance (open leak #255).
 */
#include "hwr_wit.h"

/* name, nul, rcurve, rpub, ipub, ver, home, channel, ap, calls, coord, last */
hwr_wit_case_t sg_wifi_dppInitiate_suite[] = {
	{ "success_p256_ver2",                   0, 0, 0, 0, 2, 6, 1, 2, 1, 0, 0 },
	{ "success_version_1",                   0, 0, 0, 0, 1, 6, 1, 2, 1, 0, 0 },
	{ "success_home_1",                      0, 0, 0, 0, 2, 1, 1, 2, 1, 0, 0 },
	{ "success_home_36",                     0, 0, 0, 0, 2, 36, 1, 2, 1, 0, 0 },
	{ "success_home_149",                    0, 0, 0, 0, 2, 149, 1, 2, 1, 0, 0 },
	{ "success_channel_6",                   0, 0, 0, 0, 2, 6, 6, 2, 1, 0, 0 },
	{ "success_channel_36",                  0, 0, 0, 0, 2, 6, 36, 2, 1, 0, 0 },
	{ "success_channel_149",                 0, 0, 0, 0, 2, 6, 149, 2, 1, 0, 0 },
	{ "success_ap_0",                        0, 0, 0, 0, 2, 6, 1, 0, 1, 0, 0 },
	{ "success_ap_15",                       0, 0, 0, 0, 2, 6, 1, 15, 1, 0, 0 },
	{ "success_rkey_p384",                   0, 1, 0, 0, 2, 6, 1, 2, 1, 0, 0 },
	{ "success_initiate_twice",              0, 0, 0, 0, 2, 6, 1, 2, 2, 0, 0 },
	{ "rpub_bad_base64",                     0, 0, 1, 0, 2, 6, 1, 2, 1, 0, 0 },
	{ "ipub_bad_base64",                     0, 0, 0, 1, 2, 6, 1, 2, 1, 0, 0 },
	{ "success_rkey_p521",                   0, 2, 0, 0, 2, 6, 1, 2, 1, 0, 0 },
	/* output that is wrong although the original returns RETURN_OK */
	{ "channel_0",                           0, 0, 0, 0, 2, 6, 0, 2, 1, 0, 0 },
	{ "channel_200",                         0, 0, 0, 0, 2, 6, 200, 2, 1, 0, 0 },
	{ "protocol_key_x_shorter_than_prime",   0, 0, 0, 0, 2, 6, 1, 2, 1, 1, 0 },
	{ "protocol_key_y_shorter_than_prime",   0, 0, 0, 0, 2, 6, 1, 2, 1, 2, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                            1, 0, 0, 0, 2, 6, 1, 2, 1, 0, 1 },
	{ "rpub_garbage_der",                    0, 0, 2, 0, 2, 6, 1, 2, 1, 0, 1 },
	{ "rpub_empty",                          0, 0, 3, 0, 2, 6, 1, 2, 1, 0, 1 },
	{ "ipub_garbage_der",                    0, 0, 0, 2, 2, 6, 1, 2, 1, 0, 1 },
	{ "ipub_empty",                          0, 0, 0, 3, 2, 6, 1, 2, 1, 0, 1 },
	{ "rkey_curve_not_handled_create_fails", 0, 3, 0, 0, 2, 6, 1, 2, 1, 0, 1 },
	{ NULL }
};

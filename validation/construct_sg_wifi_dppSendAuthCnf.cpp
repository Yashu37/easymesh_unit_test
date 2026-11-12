/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppSendAuthCnf
 *
 * wifi_dppSendAuthCnf(ctx): builds the DPP Authentication Confirm public action frame and sends it with wifi_sendActionFrame.  The attributes are the status TLV (0), the initiator boot hash (only for
 * mutual authentication), the responder boot hash (SHA-256 of the DER of the configured rPubKey) and the wrapped data: AES-SIV (key instance->ke by digestlen, AAD = the 6-byte frame body + the attributes in
 * front of the wrapped data) of the initiator auth tag instance->iauth.  rPubKey / iPubKey are base64 SubjectPublicKeyInfo of the bootstrap keys.  The runner captures the frame the mock wifi_sendActionFrame
 * receives, decrypts it with the same key and checks every field.
 * Inputs crossed: NULL context / session instance, digestlen 32 / 48 / 64 and an unsupported 20, mutual authentication on / off, rPubKey / iPubKey valid / valid base64 of garbage DER / empty / invalid base64,
 * ap index 0 / 2 / 15 and the session channel (frequency).
 * Expected (CORRECT behaviour): RETURN_OK for a valid session: exactly one wifi_sendActionFrame(ap_index, sta_mac, channel, frame, sizeof(frame header) + attribute bytes) with the public action header
 * (category 4, action 9), the DPP OUI 50:6F:9A:1A, crypto 1, frame type auth confirm, status 0, the boot hash(es) = SHA-256 of the DER of the COMPRESSED key (the form wifi_dppProcessAuthResponse hashes and
 * the DPP bootstrapping key hash is defined on), and the wrapped data decrypting to the initiator auth tag; afterwards data->state = STATE_DPP_AUTHENTICATED and activation_status = ActStatus_In_Progress.
 * Any key that cannot be parsed (when it is needed: rPubKey always, iPubKey for mutual authentication), an invalid base64 text or an unsupported digestlen -> RETURN_ERR, activation_status =
 * ActStatus_Failed, nothing sent and the state unchanged; a NULL context or NULL session instance -> RETURN_ERR (ActStatus_Failed for the instance) and nothing sent.  No EC_KEY is leaked.  The instance's
 * k1 / k2 / rauth / enrollee_nonce / responder_nonce arrays and pointers, the context's config object (except keyManagement), channels_list and received_frame are not touched (poisoned in the
 * runner).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wsu.h"

/* name, nul, digest, mutual, rpub, ipub, ap, freq, hashchk, last */
hwr_wsu_case_t sg_wifi_dppSendAuthCnf_suite[] = {
	{ "success_sha256",                    0, 32, 0, 0, 0, 2, 2437, 0, 0 },
	{ "success_sha384",                    0, 48, 0, 0, 0, 2, 2437, 0, 0 },
	{ "success_sha512",                    0, 64, 0, 0, 0, 2, 2437, 0, 0 },
	{ "success_mutual",                    0, 32, 1, 0, 0, 2, 2437, 0, 0 },
	{ "success_ap_0",                      0, 32, 0, 0, 0, 0, 2437, 0, 0 },
	{ "success_ap_15",                     0, 32, 0, 0, 0, 15, 2437, 0, 0 },
	{ "success_freq_5180",                 0, 32, 0, 0, 0, 2, 5180, 0, 0 },
	{ "success_ipub_garbage_not_mutual",   0, 32, 0, 0, 1, 2, 2437, 0, 0 },
	{ "digestlen_20_unsupported",          0, 20, 0, 0, 0, 2, 2437, 0, 0 },
	{ "rpub_bad_base64",                   0, 32, 0, 3, 0, 2, 2437, 0, 0 },
	{ "ipub_bad_base64",                   0, 32, 0, 0, 3, 2, 2437, 0, 0 },
	/* output that is wrong although the original returns RETURN_OK */
	{ "rpub_invalid_der",                  0, 32, 0, 1, 0, 2, 2437, 0, 0 },
	{ "rpub_empty",                        0, 32, 0, 2, 0, 2, 2437, 0, 0 },
	{ "mutual_ipub_invalid_der",           0, 32, 1, 0, 1, 2, 2437, 0, 0 },
	{ "boot_hash_compressed_form",         0, 32, 0, 0, 0, 2, 2437, 1, 0 },
	{ "boot_hash_compressed_form_mutual",  0, 32, 1, 0, 0, 2, 2437, 1, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                          1, 32, 0, 0, 0, 2, 2437, 0, 1 },
	{ "session_instance_null",             2, 32, 0, 0, 0, 2, 2437, 0, 1 },
	{ NULL }
};

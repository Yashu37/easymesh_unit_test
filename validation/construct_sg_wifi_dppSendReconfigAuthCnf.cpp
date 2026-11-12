/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppSendReconfigAuthCnf
 *
 * wifi_dppSendReconfigAuthCnf(dpp_ctx): builds the DPP Reconfiguration Authentication Confirm public action frame and sends it with wifi_sendActionFrame.  The frame carries a wrapped data attribute:
 * AES-SIV (key instance->ke by digestlen, AAD = the 6-byte DPP frame body) of the transaction id (session_data.u.reconfig_data.match_tran_id), the configurator protocol version, the initiator nonce, the
 * responder nonce (noncelen bytes each) and 4 bytes of reconfig flags (0).  The runner captures the frame the mock wifi_sendActionFrame receives, decrypts it with the same key and checks every field.
 * Inputs crossed: NULL context / session instance, digestlen 32 / 48 / 64 and an unsupported 20 / 0, noncelen 16 / 24 / 32, transaction id 0 / 17 / 255, configurator version 0 / 1 / 2, the session channel
 * number (1, 6, 14, 36, 100, 149, 165: converted to a frequency by the function) and the ap index (0 / 2 / 15).
 * Expected (CORRECT behaviour): RETURN_OK for a valid session: exactly one wifi_sendActionFrame(ap_index, sta_mac, frequency of the channel, frame, sizeof(frame header) + 4 + wrapped length) with the public
 * action header (category 4, action 9), the DPP OUI 50:6F:9A:1A, crypto 1, frame type reconfig auth confirm and the wrapped data decrypting to the five attributes; afterwards match_tran_id = 0 and the
 * session channel = the frequency of the radio channel.  An unsupported digestlen -> RETURN_ERR, enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE and nothing sent; a NULL context or NULL session
 * instance -> RETURN_ERR (enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE for the instance) and nothing sent.  The instance's k1 / k2 / rauth / iauth / enrollee_nonce / M / N / m / n / l /
 * initiator key pointers, the context's config object (except keyManagement), channels_list, received_frame and the session union (except match_tran_id) are not touched (poisoned in the runner).  Rows with
 * last = 1 break the original: they run LAST.
 */
#include "hwr_wsx.h"

/* name, nul, digest, noncelen, tran, ver, channel, ap, last */
hwr_wsx_case_t sg_wifi_dppSendReconfigAuthCnf_suite[] = {
	{ "success_sha256",              0, 32, 16, 17, 2, 6, 2, 0 },
	{ "success_sha384",              0, 48, 16, 17, 2, 6, 2, 0 },
	{ "success_sha512",              0, 64, 16, 17, 2, 6, 2, 0 },
	{ "success_noncelen_24",         0, 32, 24, 17, 2, 6, 2, 0 },
	{ "success_noncelen_32",         0, 32, 32, 17, 2, 6, 2, 0 },
	{ "success_tran_id_0",           0, 32, 16, 0, 2, 6, 2, 0 },
	{ "success_tran_id_255",         0, 32, 16, 255, 2, 6, 2, 0 },
	{ "success_version_1",           0, 32, 16, 17, 1, 6, 2, 0 },
	{ "success_version_0",           0, 32, 16, 17, 0, 6, 2, 0 },
	{ "success_channel_1",           0, 32, 16, 17, 2, 1, 2, 0 },
	{ "success_channel_14",          0, 32, 16, 17, 2, 14, 2, 0 },
	{ "success_channel_36",          0, 32, 16, 17, 2, 36, 2, 0 },
	{ "success_channel_100",         0, 32, 16, 17, 2, 100, 2, 0 },
	{ "success_channel_149",         0, 32, 16, 17, 2, 149, 2, 0 },
	{ "success_channel_165",         0, 32, 16, 17, 2, 165, 2, 0 },
	{ "success_ap_0",                0, 32, 16, 17, 2, 6, 0, 0 },
	{ "success_ap_15",               0, 32, 16, 17, 2, 6, 15, 0 },
	{ "digestlen_20_unsupported",    0, 20, 16, 17, 2, 6, 2, 0 },
	{ "digestlen_0_unsupported",     0, 0, 16, 17, 2, 6, 2, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                    1, 32, 16, 17, 2, 6, 2, 1 },
	{ "session_instance_null",       2, 32, 16, 17, 2, 6, 2, 1 },
	{ NULL }
};

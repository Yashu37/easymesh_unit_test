/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppSendConfigResponse
 *
 * wifi_dppSendConfigResponse(ctx): builds the DPP Configuration Response frame (GAS initial response + DPP status TLV + wrapped data) for the enrollee and sends it with wifi_sendActionFrame.  The
 * wrapped data is AES-SIV (key instance->ke by digestlen, AAD = the 5-byte status TLV) of the enrollee nonce (noncelen bytes) and the configuration object JSON built by dpp_build_config from ctx->config
 * (discovery ssid, credentials keyManagement + passphrase, and for enrollee version 2 with a configurator signing instance the signed connector and the csign key object).  The runner captures the frame
 * the mock wifi_sendActionFrame receives, decrypts it with the same key and checks every field.
 * Inputs crossed: NULL context / session instance, digestlen 32 / 48 / 64 and an unsupported 20, enrollee version 1 / 2, keyManagement PSK / DPP / SAE / PSK+SAE / DPP+PSK+SAE, passphrase empty / 14 / 63
 * chars, ssid empty / 13 / 31 / 32 chars (32 = no terminator), configurator signing instance + reconfig context present or absent, noncelen 16 / 24 / 32, kid of 14 or 63 chars, token 0 / 90 / 255, ap
 * index 0 / 2 / 15 and the session frequency.
 * Expected (CORRECT behaviour): RETURN_OK for a valid session: exactly one wifi_sendActionFrame(ap_index, sta_mac, channel, frame, sizeof(header) + rsp_len) with the GAS header (token echoed, status 0,
 * adv proto 221, OUI 50:6F:9A:1A, DPP protocol 1), the status TLV = 0 and the wrapped data decrypting to the enrollee nonce and a JSON configuration object with the ssid, the akm matching
 * keyManagement (psk / dpp / sae / psk+sae / dpp+psk+sae; version 1 enrollees always get psk) and the passphrase; every config object text fits in the frame buffers (no write outside json[1024]).  An
 * unsupported digestlen -> RETURN_ERR, activation_status = ActStatus_Failed and nothing sent.  A NULL context or session instance -> RETURN_ERR and nothing sent.  The instance's k1 / k2 / rauth / iauth /
 * responder_nonce / initiator_nonce / M / N / m / n / l / initiator key, the reconfig context, the csign instance's pt / bn / bnctx / prime and the context's channels_list / session union are not touched
 * (poisoned in the runner).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wsc.h"

/* name, nul, digest, keymgmt, ver, pass, ssid, csign, noncelen, kid, token, ap, freq, last */
hwr_wsc_case_t sg_wifi_dppSendConfigResponse_suite[] = {
	{ "success_psk_v1",                          0, 32, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_sha384",                          0, 48, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_sha512",                          0, 64, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_dpp_v1_forced_psk",               0, 32, 1, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_sae_v1_forced_psk",               0, 32, 2, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_psk_v2",                          0, 32, 0, 2, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_dpp_v2",                          0, 32, 1, 2, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_sae_v2",                          0, 32, 2, 2, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_dppsksae_v2_with_connector",      0, 32, 4, 2, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_dppsksae_v1_forced_psk",          0, 32, 4, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_pass_empty",                      0, 32, 0, 1, 0, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_pass_63_chars",                   0, 32, 0, 1, 2, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_ssid_empty",                      0, 32, 0, 1, 1, 0, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_ssid_31_chars",                   0, 32, 0, 1, 1, 2, 1, 16, 0, 90, 2, 2437, 0 },
	{ "success_noncelen_24",                     0, 32, 0, 1, 1, 1, 1, 24, 0, 90, 2, 2437, 0 },
	{ "success_noncelen_32",                     0, 32, 0, 1, 1, 1, 1, 32, 0, 90, 2, 2437, 0 },
	{ "success_token_0",                         0, 32, 0, 1, 1, 1, 1, 16, 0, 0, 2, 2437, 0 },
	{ "success_token_255",                       0, 32, 0, 1, 1, 1, 1, 16, 0, 255, 2, 2437, 0 },
	{ "success_ap_0",                            0, 32, 0, 1, 1, 1, 1, 16, 0, 90, 0, 2437, 0 },
	{ "success_ap_15",                           0, 32, 0, 1, 1, 1, 1, 16, 0, 90, 15, 2437, 0 },
	{ "success_freq_5180",                       0, 32, 0, 1, 1, 1, 1, 16, 0, 90, 2, 5180, 0 },
	{ "success_no_csign_v2_psk",                 0, 32, 0, 2, 1, 1, 0, 16, 0, 90, 2, 2437, 0 },
	{ "success_dppsksae_v2_long_kid_long_pass",  0, 32, 4, 2, 2, 2, 1, 16, 1, 90, 2, 2437, 0 },
	{ "digestlen_20_unsupported",                0, 20, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	/* output that is wrong although the original returns RETURN_OK */
	{ "psksae_v2_no_akm",                        0, 32, 3, 2, 1, 1, 1, 16, 0, 90, 2, 2437, 0 },
	{ "ssid_32_chars_not_terminated",            0, 32, 2, 2, 1, 3, 1, 16, 0, 90, 2, 2437, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                                1, 32, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 1 },
	{ "session_instance_null",                   2, 32, 0, 1, 1, 1, 1, 16, 0, 90, 2, 2437, 1 },
	{ NULL }
};

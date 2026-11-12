/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppReconfigInitiate
 *
 * wifi_dppReconfigInitiate(ctx): starts a DPP reconfiguration.  It creates the session instance (reconfig session: the initiator bootstrap key iPubKey gives the group / digest length / nonce length, a new
 * initiator protocol key and nonce are generated), draws a random transaction id into session_data.u.reconfig_data.tran_id[dpp_init_retries], builds the Reconfiguration Authentication Request (transaction id,
 * protocol version = configurator_version, signed connector built from the configurator signing instance and the reconfig context, initiator nonce of noncelen bytes) and sends it with wifi_sendActionFrame
 * (ap_index, sta_mac, frequency of the session channel, frame, header + attribute bytes).  The runner builds a real heap context, real P-256 keys and base64 SubjectPublicKeyInfo strings, captures the frame
 * the mock wifi_sendActionFrame receives and decodes every attribute (the connector header / body / signature included).
 * Inputs crossed: NULL context, curve of iPubKey (P-256 / P-384 / P-521), iPubKey valid / invalid base64 / garbage DER / empty, cSignInstance or reconfigCtx NULL, kid length, dpp_init_retries (0, 5, 119,
 * 120 = first index past tran_id[120], and the first byte past the end of the context), configurator_version 1 / 2, session channel number (valid, 0, 200) and ap index.
 * Expected (CORRECT behaviour): RETURN_OK for a valid context: exactly one wifi_sendActionFrame(ap_index, sta_mac, channel_to_frequency(channel), frame, header + attributes) with the public action header
 * (category 4, action 9), DPP OUI 50:6F:9A:1A, crypto 1, frame type reconfig auth request, then the transaction id attribute (the value stored in tran_id[dpp_init_retries]), the protocol version attribute, the
 * connector attribute (base64url header {typ dppCon, kid, alg} . body {netAccessKey x / y of the reconfig key} . signature) and the initiator nonce attribute (noncelen bytes = the instance's nonce).  A NULL
 * context, a session instance that cannot be created (invalid / empty iPubKey), a missing signing instance / reconfig context (no connector) or a session channel without a frequency -> RETURN_ERR and nothing
 * sent; dpp_init_retries >= 120 -> RETURN_ERR without writing outside tran_id[120] (the byte after it is iPubKey[0], used to create the session).  The context's config object (except reconfigCtx /
 * cSignInstance / keyManagement), channels_list, received_frame, the unused tail of the session union and the other tran_id entries, the reconfig context's bnctx / prime / key / pt / crv members and the
 * signing instance's bnctx / prime / pt / bn members are not touched (poisoned in the runner).  Rows with last = 1 break the original: they run LAST.  Not counted here: leaks that belong to
 * create_dpp_session_instance (the initiator bootstrap EC_KEY is kept alive by the instance's group pointer).
 */
#include "hwr_wrz.h"

/* name, nul, curve, ipub, csign, kid, retries, ver, channel, ap, last */
hwr_wrz_case_t sg_wifi_dppReconfigInitiate_suite[] = {
	{ "success_p256_ch1",                0, 0, 0, 0, 0, 0, 2, 1, 2, 0 },
	{ "success_ch6",                     0, 0, 0, 0, 0, 0, 2, 6, 2, 0 },
	{ "success_ch36",                    0, 0, 0, 0, 0, 0, 2, 36, 2, 0 },
	{ "success_ch149",                   0, 0, 0, 0, 0, 0, 2, 149, 2, 0 },
	{ "success_retries_5",               0, 0, 0, 0, 0, 5, 2, 1, 2, 0 },
	{ "success_retries_119",             0, 0, 0, 0, 0, 119, 2, 1, 2, 0 },
	{ "success_version_1",               0, 0, 0, 0, 0, 0, 1, 1, 2, 0 },
	{ "success_version_2",               0, 0, 0, 0, 0, 0, 2, 1, 2, 0 },
	{ "success_kid_63_chars",            0, 0, 0, 0, 1, 0, 2, 1, 2, 0 },
	{ "success_ap_0",                    0, 0, 0, 0, 0, 0, 2, 1, 0, 0 },
	{ "success_ap_15",                   0, 0, 0, 0, 0, 0, 2, 1, 15, 0 },
	{ "cSign_instance_null",             0, 0, 0, 1, 0, 0, 2, 1, 2, 0 },
	{ "reconfig_ctx_null",               0, 0, 0, 2, 0, 0, 2, 1, 2, 0 },
	/* output that is wrong although the original returns RETURN_OK */
	{ "channel_0_frequency_0",           0, 0, 0, 0, 0, 0, 2, 0, 2, 0 },
	{ "channel_200_frequency_0",         0, 0, 0, 0, 0, 0, 2, 200, 2, 0 },
	{ "retries_120_overwrites_ipubkey",  0, 0, 0, 0, 0, 120, 2, 1, 2, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                        1, 0, 0, 0, 0, 0, 2, 1, 2, 1 },
	{ "ipub_bad_base64",                 0, 0, 1, 0, 0, 0, 2, 1, 2, 1 },
	{ "ipub_garbage_der",                0, 0, 2, 0, 0, 0, 2, 1, 2, 1 },
	{ "ipub_empty",                      0, 0, 3, 0, 0, 0, 2, 1, 2, 1 },
	{ "retries_past_context_end",        0, 0, 0, 0, 0, -1, 2, 1, 2, 1 },
	{ "success_ipub_p384",               0, 1, 0, 0, 0, 0, 2, 1, 2, 1 },
	{ "success_ipub_p521",               0, 2, 0, 0, 0, 0, 2, 1, 2, 1 },
	{ NULL }
};

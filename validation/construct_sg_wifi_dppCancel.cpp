/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppCancel
 *
 * wifi_dppCancel(ctx): cancels the DPP session: delete_dpp_session_instance frees the session instance (N, M, responder protocol point, for a reconfig session the responder connector, the initiator protocol
 * key, bn context, prime, n, m, y, x and the instance block itself, each only when not NULL) and sets session_data.instance = NULL.  The runner builds a real instance with every member allocated (P-256 group,
 * BIGNUMs, EC points, EC key, BN_CTX) in a heap block like create_dpp_session_instance, so ASan sees any double free, use after free or free of something the function does not own.
 * Inputs crossed: NULL context / session instance, config / reconfig session type, each instance member NULL in turn (N, M, responder protocol point, responder connector, initiator protocol key, bn
 * context, prime, n, m, y, x), an instance with all members NULL and a second wifi_dppCancel on the same context.
 * Expected (CORRECT behaviour): RETURN_OK, session_data.instance = NULL, everything the instance owns freed (nothing leaked, checked with a LeakSanitizer pass after each case) and nothing it only borrows (the
 * EC_GROUP the instance points at) freed; a second cancel (or a cancel without a session) is a no-op that returns RETURN_OK; a NULL context -> RETURN_ERR.  The instance's group / hashfcn / counters /
 * k1 / k2 / ke / rauth / iauth / nonce arrays and the context's config / channels_list / received_frame / session union / sta_mac are not touched (poisoned in the runner).  Rows with last = 1 break the
 * original: they run LAST.
 */
#include "hwr_wdk.h"

/* name, nul, session, skip, calls, last */
hwr_wdk_case_t sg_wifi_dppCancel_suite[] = {
	{ "cancel_config_session",                   0, 0, 0, 1, 0 },
	{ "cancel_reconfig_session",                 0, 1, 0, 1, 0 },
	{ "skip_N",                                  0, 0, 1, 1, 0 },
	{ "skip_M",                                  0, 0, 2, 1, 0 },
	{ "skip_responder_proto_pt",                 0, 0, 3, 1, 0 },
	{ "skip_responder_connector_reconfig",       0, 1, 4, 1, 0 },
	{ "skip_initiator_proto_key",                0, 0, 5, 1, 0 },
	{ "skip_bnctx",                              0, 0, 6, 1, 0 },
	{ "skip_prime",                              0, 0, 7, 1, 0 },
	{ "skip_n",                                  0, 0, 8, 1, 0 },
	{ "skip_m",                                  0, 0, 9, 1, 0 },
	{ "skip_y",                                  0, 0, 10, 1, 0 },
	{ "skip_x",                                  0, 0, 11, 1, 0 },
	{ "empty_instance_all_members_null",         0, 0, 12, 1, 0 },
	{ "empty_reconfig_instance",                 0, 1, 12, 1, 0 },
	/* inputs that crash the original: run LAST */
	{ "ctx_null",                                1, 0, 0, 1, 1 },
	{ "session_instance_null",                   2, 0, 0, 1, 1 },
	{ "cancel_twice_second_call_instance_null",  0, 0, 0, 2, 1 },
	{ NULL }
};

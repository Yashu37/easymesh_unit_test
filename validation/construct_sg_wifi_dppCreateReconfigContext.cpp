/*
 * UNIT TEST (input constructor): construct_sg_wifi_dppCreateReconfigContext
 *
 * wifi_dppCreateReconfigContext(ap_index, net_access_key, inst, pub).  Inputs crossed: net_access_key = base64 DER EC private key of curve P-256 / P-384 / P-521 / secp256k1 (unsupported), invalid base64,
 * empty, truncated, valid base64 that is no EC key, 1400 characters of valid base64 (decodes to 1050 bytes, more than the 1024-byte keyasn1; the write happens inside libcrypto, which ASan does not instrument, so only the result is checked), NULL; inst NULL / pointer to NULL / pointer to an existing context (one made by an earlier
 * successful call, or a runner-made one); pub NULL / an exactly sized block for the base64 public key; one call or two consecutive calls on the same instance pointer; ap_index 0 / 7.
 * Expected (CORRECT behaviour): inst NULL -> RETURN_ERR; an existing context is released exactly once and replaced; a valid P-256 / P-384 / P-521 key -> RETURN_OK, *inst holds the context (bn ctx, EC key,
 * public point, x / y / prime, curve name "P-256" / "P-384" / "P-521") and pub holds the base64 of the DER public key; every failure (NULL / invalid / empty / truncated / non-EC / too long key, unsupported
 * curve, NULL pub) -> RETURN_ERR with *inst left NULL and no context left allocated (no dangling pointer that a retry would free again).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wrc.h"

/* name, calls, {key ids}, ap, inst_null, key_null, pub_null, pre_existing, last */
hwr_wrc_case_t sg_wifi_dppCreateReconfigContext_suite[] = {
	{ "p256_key_ok",                       1, { 0, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "p384_key_ok",                       1, { 1, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "p521_key_ok",                       1, { 2, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "ap_index_7_p256",                   1, { 0, -1 }, 7, 0, 0, 0, 0, 0 },
	{ "existing_runner_context_replaced",  1, { 0, -1 }, 0, 0, 0, 0, 1, 0 },
	{ "existing_runner_context_bad_key",   1, { 4, -1 }, 0, 0, 0, 0, 1, 0 },
	{ "inst_null",                         1, { 0, -1 }, 0, 1, 0, 0, 0, 0 },
	{ "unsupported_curve_secp256k1",       1, { 3, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "invalid_base64_key",                1, { 4, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "empty_key",                         1, { 5, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "truncated_key",                     1, { 6, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "valid_base64_not_an_ec_key",        1, { 7, -1 }, 0, 0, 0, 0, 0, 0 },
	{ "recreate_over_created_p256",        2, { 0, 0 }, 0, 0, 0, 0, 0, 1 },
	{ "recreate_p384_then_p256",           2, { 1, 0 }, 0, 0, 0, 0, 0, 1 },
	{ "retry_after_invalid_base64",        2, { 4, 0 }, 0, 0, 0, 0, 0, 1 },
	{ "retry_after_empty_key",             2, { 5, 0 }, 0, 0, 0, 0, 0, 1 },
	{ "net_access_key_null",               1, { 0, -1 }, 0, 0, 1, 0, 0, 1 },
	{ "pub_null",                          1, { 0, -1 }, 0, 0, 0, 1, 0, 1 },
	{ "key_1400_chars_too_long",            1, { 8, -1 }, 0, 0, 0, 0, 0, 0 },
	{ NULL }
};

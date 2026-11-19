/*
 * TEST CASES / CONSTRUCTOR: construct_ec_b64key
 *
 * kinds 0-2: a freshly generated P-256 / P-384 / P-521 public key as base64 DER (SubjectPublicKeyInfo) - the call must return an
 * equal key; kind 3: n raw bytes (i*7+1) as base64 (valid base64, not DER) - the call must return NULL; kind 4: a literal string.
 * The input string has a 128 byte guard behind its terminator that the runner poisons. Cases named crash_* ABORT on the original
 * code (a base64 string that decodes to more than 1023 bytes overflows key[1024]): they run last and UNFORKED so a plain `make`
 * stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec_b64key.h"

namespace ekb {
/* {name, kind, nbytes, text, suffix, expect_key, crash} */
test_case_t suite[] = {
 {"ok_p256_public_key",                  0, 0, NULL, "", true, false},
 {"ok_p384_public_key",                  1, 0, NULL, "", true, false},
 {"ok_p521_public_key",                  2, 0, NULL, "", true, false},
 {"ok_p256_trailing_newline",            0, 0, NULL, "\n", true, false},
 {"ok_empty_string_rejected",            4, 0, "", "", false, false},
 {"ok_not_base64_rejected",              4, 0, "!!!!", "", false, false},
 {"ok_length_not_multiple_of_4_rejected", 4, 0, "QUJDRA", "", false, false},
 {"ok_valid_base64_not_der_rejected",    3, 100, NULL, "", false, false},
 {"ok_raw_1022_bytes_rejected",          3, 1022, NULL, "", false, false},
 {"ok_raw_1023_bytes_fills_key_exactly", 3, 1023, NULL, "", false, false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_raw_1024_bytes_decodes_to_1026", 3, 1024, NULL, "", false, true},
 {"crash_raw_1100_bytes",                3, 1100, NULL, "", false, true},
 {"crash_raw_2000_bytes",                3, 2000, NULL, "", false, true},
 {"crash_raw_100000_bytes",              3, 100000, NULL, "", false, true},
 {NULL, 0, 0, NULL, NULL, false, false}
};

static std::string b64(const unsigned char *d, size_t n)
{
    std::string o(((n + 2) / 3) * 4 + 1, '\0'); int r = EVP_EncodeBlock((unsigned char *)&o[0], d, (int)n); o.resize((size_t)r); return o;
}
void construct_input(const test_case_t *tc)
{
    std::string text;
    g_ref = NULL;
    if (tc->kind <= 2) {
        int nid = tc->kind == 0 ? NID_X9_62_prime256v1 : tc->kind == 1 ? NID_secp384r1 : NID_secp521r1;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); EVP_PKEY_keygen_init(c); EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid);
        EVP_PKEY_keygen(c, &g_ref); EVP_PKEY_CTX_free(c);
        unsigned char *der = NULL; int dl = i2d_PUBKEY(g_ref, &der); text = b64(der, (size_t)dl); OPENSSL_free(der);
    } else if (tc->kind == 3) {
        std::string raw(tc->nbytes, '\0'); for (size_t i = 0; i < tc->nbytes; i++) raw[i] = (char)(i * 7 + 1);
        text = b64((const unsigned char *)raw.data(), raw.size());
    } else text = tc->text;
    text += tc->suffix;
    g_input.clear(); g_input.reserve(text.size() + 4 * EKB_GUARD);   /* the heap buffer has room behind the terminator for the runner's guard */
    g_input = text;
}
void teardown(void) { if (g_ref) EVP_PKEY_free(g_ref); g_ref = NULL; g_input.clear(); }
} /* namespace ekb */

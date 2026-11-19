/* em_crypto_t::ec_key_from_base64_der harness types (namespace ekb). Own header, kept out of common.h so `make` stays incremental. */
#ifndef EC_B64KEY_H
#define EC_B64KEY_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "common.h"

namespace ekb {
#define EKB_GUARD 128
typedef EVP_PKEY SSL_KEY;
/* EVP_DecodeBlock lives in the (uninstrumented) libcrypto, so ASan cannot see it write past the caller's buffer. The wrapper makes
 * that write visible: the real EVP_DecodeBlock decodes into a temporary heap buffer, which is then memcpy'd (intercepted by ASan) to
 * the caller's buffer, exactly the bytes libcrypto would have written there. */
static inline int asan_visible_decode_block(unsigned char *t, const unsigned char *f, int n)
{
    unsigned char *tmp = (unsigned char *)calloc(1, (size_t)n / 4 * 3 + 8);
    int r = EVP_DecodeBlock(tmp, f, n);
    if (r > 0) memcpy(t, tmp, (size_t)r);
    free(tmp);
    return r;
}
#define EVP_DecodeBlock asan_visible_decode_block
class em_crypto_t {
public:
    static SSL_KEY* ec_key_from_base64_der(const std::string& base64_der_pubkey);
};
typedef struct {
    const char *test_name;
    int kind;                /* 0 P-256, 1 P-384, 2 P-521 public key (DER SubjectPublicKeyInfo, base64), 3 raw bytes (not DER), 4 literal text */
    size_t nbytes;           /* kind 3: number of raw bytes encoded */
    const char *text;        /* kind 4: the string handed over */
    const char *suffix;      /* appended to the base64 text */
    bool expect_key;         /* a valid key must come back (and equal the generated one) */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern std::string g_input;
extern EVP_PKEY *g_ref;      /* the generated key (kinds 0-2) */
void construct_input(const test_case_t *tc);
SSL_KEY *invoke(void);
void teardown(void);
}
void run_all_tests_ec_b64key(void);
#endif

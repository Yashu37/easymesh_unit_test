/* em_crypto_t::kdf_hash_length harness types (namespace kdl). Own header, kept out of common.h so `make` stays incremental. */
#ifndef KDF_LEN_H
#define KDF_LEN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "common.h"

namespace kdl {
#define KDL_GUARD 128
static inline uint16_t SWAP_LITTLE_ENDIAN(uint16_t x) { return x; }   /* util.h on a little endian host */
class em_crypto_t {
public:
    static uint8_t platform_hmac_hash(const EVP_MD *hashing_algo, uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac);
    static bool kdf_hash_length(const EVP_MD *algo, const uint8_t *key, size_t key_len, const char *label,
                                const uint8_t *context, size_t context_len, uint8_t *output, size_t output_len);
};
/* every input buffer is exactly its length between two poisoned 128 byte guards: [guard][bytes][guard] */
typedef struct { uint8_t *raw; uint8_t *p; size_t n; } gbuf_t;
typedef struct {
    const char *test_name;
    int algo;                /* 0 sha256, 1 sha384, 2 sha512, -1 NULL */
    size_t key_len;
    const char *label;       /* NULL passes a NULL label */
    size_t context_len;
    bool null_context;
    bool null_key;
    bool null_output;
    size_t output_len;
    size_t out_buf;          /* size of the output buffer */
    int expect_ret;
    bool check_output;       /* compare output with the independently computed KDF */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern gbuf_t g_key, g_label, g_ctx, g_out;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
const EVP_MD *algo_of(int a);
void teardown(void);
}
void run_all_tests_kdf_len(void);
#endif

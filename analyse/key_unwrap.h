/* em_crypto_t::aes_key_unwrap harness types (namespace aku). Own header, kept out of common.h so `make` stays incremental. */
#ifndef KEY_UNWRAP_H
#define KEY_UNWRAP_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "common.h"

namespace aku {
#define AKU_GUARD 128
#define AES_BLOCK_SIZE 16
class em_crypto_t {
public:
    static uint32_t platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len, bool disable_padding);
    static uint8_t aes_key_unwrap(uint8_t *kek, size_t kek_len, uint8_t *wrapped, uint32_t wrapped_len, uint8_t *unwrapped, uint32_t *unwrapped_len);
};
/* every buffer is exactly its length between two poisoned 128 byte guards: [guard][bytes][guard] */
typedef struct { uint8_t *raw; uint8_t *p; size_t n; } gbuf_t;
typedef struct {
    const char *test_name;
    size_t kek_len;          /* length of the KEK handed over (the buffer has exactly this size) */
    uint32_t plain_len;      /* length of the plaintext key that is wrapped by the reference (wrapped_len = plain_len + 8) */
    uint32_t wrapped_len;    /* wrapped_len argument, 0 = plain_len + 8 */
    int out_buf;             /* size of the unwrapped buffer: -1 = wrapped_len - 8 (what the header documents), -2 = wrapped_len (the real caller) */
    bool tamper;             /* flip a byte of the wrapped key (integrity check must fail) */
    bool null_kek, null_wrapped, null_out, null_outlen;
    int expect_ret;
    bool check_output;
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern gbuf_t g_kek, g_wrapped, g_out, g_plain;
extern uint32_t g_ulen;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_key_unwrap(void);
#endif

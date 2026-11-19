/* em_crypto_t::wps_key_derivation_function harness types (namespace wkd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef WPS_KDF_H
#define WPS_KDF_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "common.h"

namespace wkd {
#define WKD_GUARD 128
#define SHA256_MAC_LEN 32
class em_crypto_t {
public:
    inline static uint8_t platform_hmac_SHA256(uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac)
    { return platform_hmac_hash(EVP_sha256(), key, keylen, num_elem, addr, len, hmac); }
    static uint8_t platform_hmac_hash(const EVP_MD *hashing_algo, uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac);
    static void append_u32_net(const uint32_t *memory_pointer, uint8_t **packet_ppointer);
    static uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, size_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len);
};
/* every input buffer is exactly its length between two poisoned 128 byte guards: [guard][bytes][guard] */
typedef struct { uint8_t *raw; uint8_t *p; size_t n; } gbuf_t;
typedef struct {
    const char *test_name;
    uint32_t res_len;        /* requested key length */
    size_t res_buf;          /* size of the result buffer (normally res_len) */
    const char *label;       /* NULL passes a NULL label */
    size_t prefix_len;
    bool null_prefix;
    bool null_key;
    bool null_res;
    int expect_ret;
    bool check_output;       /* compare res with the independently computed KDF */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern gbuf_t g_key, g_prefix, g_label, g_res;
void construct_input(const test_case_t *tc);
int invoke(const test_case_t *tc);
void teardown(void);
}
void run_all_tests_wps_kdf(void);
#endif

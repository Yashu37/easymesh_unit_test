/*
 * HANDLER: em_crypto_t::hash_to_hex_string
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): both overloads of em_crypto_t::hash_to_hex_string
 * (src/em/crypto/em_crypto.cpp). Local array: the variable length output[hash_len * 2 + 1] on the stack (fixes 1-2 applied, start fix n /
 * end fix n markers: NULL hash returns an empty string, the stack array is replaced by a heap std::string).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_hex.h"

namespace hhx {
uint8_t *g_raw = NULL; uint8_t *g_hash = NULL; size_t g_len = 0;

/* --- copied verbatim --- */
std::string em_crypto_t::hash_to_hex_string(const uint8_t *hash, size_t hash_len) {
/* start fix 1 */
    if (hash == NULL) {
        return std::string();
    }
/* end fix 1 */
/* start fix 2 */
    static const char hex_digits[] = "0123456789abcdef";
    std::string output;
    for (size_t i = 0; i < hash_len; i++) {
        output += hex_digits[hash[i] >> 4];
        output += hex_digits[hash[i] & 0x0F];
    }
    return output;
/* end fix 2 */
}

std::string em_crypto_t::hash_to_hex_string(const std::vector<uint8_t>& hash)
{
    return hash_to_hex_string(hash.data(), hash.size());
}

std::string invoke(const test_case_t *tc)
{
    if (tc->use_vector) { std::vector<uint8_t> v(g_hash, g_hash + g_len); return em_crypto_t::hash_to_hex_string(v); }
    return em_crypto_t::hash_to_hex_string(tc->null_hash ? NULL : g_hash, g_len);
}
} /* namespace hhx */

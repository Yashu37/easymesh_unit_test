/*
 * HANDLER: em_crypto_t::hash_to_hex_string
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): both overloads of em_crypto_t::hash_to_hex_string
 * (src/em/crypto/em_crypto.cpp). Local array: the variable length output[hash_len * 2 + 1] on the stack.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_hex.h"

namespace hhx {
uint8_t *g_raw = NULL; uint8_t *g_hash = NULL; size_t g_len = 0;

/* --- copied verbatim --- */
std::string em_crypto_t::hash_to_hex_string(const uint8_t *hash, size_t hash_len) {
    char output[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
    return std::string(output);
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

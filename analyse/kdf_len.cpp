/*
 * HANDLER: em_crypto_t::kdf_hash_length
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): em_crypto_t::kdf_hash_length and platform_hmac_hash (the real OpenSSL
 * HMAC it calls), src/em/crypto/em_crypto.cpp. Local arrays: hash[SHA512_DIGEST_LENGTH], addr[4], len[4] (fix 1 applied, start fix 1 /
 * end fix 1 markers: reject a NULL context with a length; the two length wrap failures are left original). Every input buffer of the
 * harness has exactly its length between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdf_len.h"

namespace kdl {
gbuf_t g_key, g_label, g_ctx, g_out;

/* --- copied verbatim --- */
uint8_t em_crypto_t::platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac)
{

    if (!key || !addr || !len || !hmac || keylen == 0) {
        return 0;
    }

    int mdlen_int = EVP_MD_size(hashing_algo);
    if (mdlen_int < 0) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX   *ctx;
    EVP_PKEY     *pkey;
    size_t mdlen = static_cast<size_t> (mdlen_int);
#else
    HMAC_CTX     *ctx;
    unsigned int mdlen = static_cast<unsigned int> (mdlen_int);
#endif
    size_t        i;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ctx = EVP_MD_CTX_new();
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
#else
    HMAC_CTX  ctx_aux;
    ctx = &ctx_aux;

    HMAC_CTX_init(ctx);
#endif
    if (!ctx) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (pkey == NULL) {
        goto bail;
    }
    if (EVP_DigestSignInit(ctx, NULL, hashing_algo, NULL, pkey) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        if (EVP_DigestSignUpdate(ctx, addr[i], len[i]) != 1) {
            goto bail;
        }
    }

    if (EVP_DigestSignFinal(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#else
    if (HMAC_Init_ex(ctx, key, static_cast<int> (keylen), hashing_algo, NULL) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        HMAC_Update(ctx, addr[i], len[i]);
    }

    if (HMAC_Final(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#endif

    /* Release resources */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;

bail:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    //em_util_info_print(EM_CONF," %s:%d\n",__func__,__LINE__);
    return 0;
}

bool em_crypto_t::kdf_hash_length(const EVP_MD *algo,
                     const uint8_t *key, size_t key_len,
                     const char *label,
                     const uint8_t *context, size_t context_len,
                     uint8_t *output, size_t output_len) {
    
    // Input validation
    if (!algo || !key || key_len == 0 || !label || !output || output_len == 0) {
        return false;
    }
/* start fix 1 */
    if (context == NULL && context_len > 0) {
        return false;
    }
/* end fix 1 */
    
    size_t hash_len = static_cast<size_t>(EVP_MD_size(algo));
    if (hash_len == 0 || hash_len > 64) {  // Sanity check on hash size
        return false;
    }
    
    size_t iterations = (output_len + hash_len - 1) / hash_len;
    if (iterations > UINT16_MAX) {  // Counter must fit in uint16_t
        return false;
    }
    
    size_t offset = 0;
    uint8_t hash[SHA512_DIGEST_LENGTH]; // Max hash size
    
    uint8_t *addr[4];
    size_t len[4];
    
    addr[1] = reinterpret_cast<uint8_t *>(const_cast<char *>(label));
    len[1] = strlen(label);
    
    addr[2] = const_cast<uint8_t *>(context);
    len[2] = context_len;
    
    // Length encoded as 16-bit little-endian
    uint16_t length_bits = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(output_len * 8));
    addr[3] = reinterpret_cast<uint8_t*>(&length_bits);
    len[3] = 2;
    
    // Loop counter encoded as 16-bit little-endian
    uint16_t counter_le;
    
    for (size_t i = 1; i <= iterations; i++) {
        // Encode counter in little-endian
        counter_le = SWAP_LITTLE_ENDIAN(static_cast<uint16_t>(i));
        addr[0] = reinterpret_cast<uint8_t*>(&counter_le);
        len[0] = 2;
        
        // Compute HMAC
        if (!em_crypto_t::platform_hmac_hash(algo, const_cast<uint8_t*>(key), key_len, 4, addr, len, hash)) {
            return false;
        }
        
        // Copy to output
        size_t to_copy = (offset + hash_len > output_len) ? 
                         (output_len - offset) : hash_len;
        memcpy(output + offset, hash, to_copy);
        
        offset += to_copy;
    }

    return true;
}

const EVP_MD *algo_of(int a) { return a == 0 ? EVP_sha256() : a == 1 ? EVP_sha384() : a == 2 ? EVP_sha512() : NULL; }
int invoke(const test_case_t *tc)
{
    return em_crypto_t::kdf_hash_length(algo_of(tc->algo), tc->null_key ? NULL : g_key.p, tc->key_len, tc->label ? (const char *)g_label.p : NULL,
                                        tc->null_context ? NULL : g_ctx.p, tc->context_len, tc->null_output ? NULL : g_out.p, tc->output_len);
}
} /* namespace kdl */

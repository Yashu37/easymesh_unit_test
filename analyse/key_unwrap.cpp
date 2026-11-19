/*
 * HANDLER: em_crypto_t::aes_key_unwrap (fixes 1-2 applied, start fix n / end fix n markers: reject NULL kek / wrapped / unwrapped /
 * unwrapped_len, decrypt a private copy and write only wrapped_len - 8 bytes to the output)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): em_crypto_t::aes_key_unwrap and platform_cipher_decrypt (the real
 * OpenSSL AES key wrap decrypt it calls), src/em/crypto/em_crypto.cpp. Local arrays: iv[8] here, buf[AES_BLOCK_SIZE] and err_buf[256]
 * in platform_cipher_decrypt. Every buffer of the harness has exactly its length between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "key_unwrap.h"

namespace aku {
gbuf_t g_kek, g_wrapped, g_out, g_plain; uint32_t g_ulen = 0;

/* --- copied verbatim --- */
uint32_t em_crypto_t::platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len, bool disable_padding)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             plen, len;
    uint8_t         buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    
    // For wrap ciphers, set the appropriate flags BEFORE init
    if (EVP_CIPHER_mode(cipher_type) == EVP_CIPH_WRAP_MODE) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptInit_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    if (disable_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    
    plen = static_cast<int> (data_len);
    if (EVP_DecryptUpdate(ctx, data, &plen, data, static_cast<int> (data_len)) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptUpdate failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("%s:%d EVP_DecryptFinal_ex failed: %s\n", __func__, __LINE__, err_buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }
    plen += len;

    // For non-wrap ciphers, len should be 0 after final
    if (disable_padding && EVP_CIPHER_mode(cipher_type) != EVP_CIPH_WRAP_MODE && len != 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(ctx);
#else
        EVP_CIPHER_CTX_free(ctx);
#endif
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return static_cast<uint32_t>(plen);
}

uint8_t em_crypto_t::aes_key_unwrap(uint8_t *kek, size_t kek_len,
                                    uint8_t *wrapped, uint32_t wrapped_len,
                                    uint8_t *unwrapped, uint32_t *unwrapped_len)
{
    const EVP_CIPHER *cipher;
    
    // Default IV for AES Key Wrap (RFC 3394 2.2.3.1)
    uint8_t iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
    
/* start fix 1 */
    if (kek == NULL || wrapped == NULL || unwrapped == NULL || unwrapped_len == NULL) {
        return 0;
    }
/* end fix 1 */
    // Select cipher based on KEK length
    switch(kek_len) {
        case 16: cipher = EVP_aes_128_wrap(); break;
        case 24: cipher = EVP_aes_192_wrap(); break;
        case 32: cipher = EVP_aes_256_wrap(); break;
        default: return 0;
    }
    
    // Validate wrapped key length (must be multiple of 8, minimum 24)
    if (wrapped_len < 24 || (wrapped_len % 8) != 0) {
        return 0;
    }
    
/* start fix 2 */
    // platform_cipher_decrypt works in-place, so decrypt a private copy and give the caller only wrapped_len - 8 bytes (header contract)
    std::vector<uint8_t> work(wrapped, wrapped + wrapped_len);
    
    // Use platform_cipher_decrypt with padding DISABLED for wrap mode (true = disable padding)
    if (platform_cipher_decrypt(cipher, kek, iv, work.data(), wrapped_len, true) == 0) {
        return 0;
    }
    memcpy(unwrapped, work.data(), wrapped_len - 8);
/* end fix 2 */
    
    // Output length is 8 bytes less than wrapped length
    *unwrapped_len = wrapped_len - 8;
    
    return 1;
}

int invoke(const test_case_t *tc)
{
    uint32_t wl = tc->wrapped_len ? tc->wrapped_len : tc->plain_len + 8;
    return em_crypto_t::aes_key_unwrap(tc->null_kek ? NULL : g_kek.p, tc->kek_len, tc->null_wrapped ? NULL : g_wrapped.p, wl,
                                       tc->null_out ? NULL : g_out.p, tc->null_outlen ? NULL : &g_ulen);
}
} /* namespace aku */

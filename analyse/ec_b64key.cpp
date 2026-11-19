/*
 * HANDLER: em_crypto_t::ec_key_from_base64_der
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): em_crypto_t::ec_key_from_base64_der (src/em/crypto/em_crypto.cpp), real
 * OpenSSL d2i_PUBKEY. Local array: uint8_t key[1024] (EVP_DecodeBlock goes through asan_visible_decode_block, see ec_b64key.h, so
 * ASan sees libcrypto's write into key[]). The input string has a poisoned guard behind its terminator.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec_b64key.h"

namespace ekb {
std::string g_input; EVP_PKEY *g_ref = NULL;

/* --- copied verbatim --- */
SSL_KEY* em_crypto_t::ec_key_from_base64_der(const std::string& base64_der_pubkey) 
{

    uint8_t key[1024];
    
    memset(key, 0, sizeof(key));

    int len = EVP_DecodeBlock(key, reinterpret_cast<const uint8_t*>(base64_der_pubkey.c_str()), static_cast<int> (base64_der_pubkey.length()));
    if (len < 0) {
        printf("%s:%d Failed to decode base 64 public key\n", __func__, __LINE__);
        return NULL;
    }

    const uint8_t *ptr = key;
#if OPENSSL_VERSION_NUMBER < 0x30000000L 
    EC_KEY *ec_key = d2i_EC_PUBKEY(NULL, &ptr, len);
    if (ec_key == NULL) {
        printf("%s:%d Failed to create EC key from DER\n", __func__, __LINE__);
        return NULL;
    }

    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

    return ec_key;
#else
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &ptr, len);

    if (!pkey) {
        printf("%s:%d Failed to create EVP_PKEY from DER\n", __func__, __LINE__);
        return NULL;
    }
    return pkey;
#endif

}

SSL_KEY *invoke(void) { return em_crypto_t::ec_key_from_base64_der(g_input); }
} /* namespace ekb */

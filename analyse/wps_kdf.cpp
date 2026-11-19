/*
 * HANDLER: em_crypto_t::wps_key_derivation_function
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): em_crypto_t::wps_key_derivation_function, append_u32_net and
 * platform_hmac_hash (the real OpenSSL HMAC-SHA256 behind platform_hmac_SHA256), all in src/em/crypto/em_crypto.cpp. Local arrays:
 * i_buf[4], key_bits[4], addr[4], len[4], hash[32]. Every input buffer of the harness has exactly its length between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wps_kdf.h"

namespace wkd {
gbuf_t g_key, g_prefix, g_label, g_res;

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

void em_crypto_t:: append_u32_net(const uint32_t *memory_pointer, uint8_t **packet_ppointer)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    **packet_ppointer = *(((uint8_t *)memory_pointer)+0); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+1); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+2); (*packet_ppointer)++;
    **packet_ppointer = *(((uint8_t *)memory_pointer)+3); (*packet_ppointer)++;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+3)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+2)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+1)); (*packet_ppointer)++;
    **packet_ppointer = *((reinterpret_cast<uint8_t *> (const_cast<uint32_t*>(memory_pointer))+0)); (*packet_ppointer)++;
#else
#error You must specify your architecture endianess
#endif
}

uint8_t em_crypto_t:: wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, size_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len)
{
    uint8_t i_buf[4];
    uint8_t key_bits[4];

    uint8_t   *addr[4];
    size_t   len[4];

    uint32_t i, iter;

    uint8_t  hash[SHA256_MAC_LEN] = {0};
    uint8_t *opos;

    uint32_t left;

    uint8_t  *p;
    uint32_t  aux;

    aux = res_len * 8;
    p   = key_bits;

    append_u32_net(&aux, &p);

    addr[0] = i_buf;
    addr[1] = label_prefix;
    addr[2] = reinterpret_cast<uint8_t *> (label);
    addr[3] = key_bits;
    len[0]  = sizeof(i_buf);
    len[1]  = label_prefix_len;
    len[2]  = strlen(label);
    len[3]  = sizeof(key_bits);

    iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
    opos = res;
    left = res_len;

    for (i = 1; i <= iter; i++) {
        p = i_buf;
        append_u32_net(&i, &p);

        if (platform_hmac_SHA256(key, SHA256_MAC_LEN, 4, addr, len, hash) != 1) {
            //em_util_info_print(EM_CONF,"platform_hmac_SHA256 error %s:%d\n" ,__func__,__LINE__);
            return 0;
        }

        if (i < iter) {
            memcpy(opos, hash, SHA256_MAC_LEN);
            opos += SHA256_MAC_LEN;
            left -= SHA256_MAC_LEN;
        } else {
            memcpy(opos, hash, left);
        }
    }
    return 1; 
}

int invoke(const test_case_t *tc)
{
    return em_crypto_t::wps_key_derivation_function(tc->null_key ? NULL : g_key.p, tc->null_prefix ? NULL : g_prefix.p, tc->prefix_len,
                                                    tc->label ? (char *)g_label.p : NULL, tc->null_res ? NULL : g_res.p, tc->res_len);
}
} /* namespace wkd */

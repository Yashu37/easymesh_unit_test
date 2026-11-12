/*
 * HANDLER: wifi_dppProcessAuthResponse (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:2571-2837 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-9 (start fix n / end fix n markers; the unfixed copy is the reproducer).  It handles a received DPP Authentication Response
 * (ctx->received_frame = public action frame body + attributes): reads the protocol version and status, checks the responder boot hash against the configured rPubKey, takes the responder protocol key,
 * derives N = pi * PR and the second intermediate key k2, decrypts the wrapped data (AES-SIV, AAD = frame header + the attributes in front of it) into primary[512], takes the responder nonce / capabilities /
 * initiator nonce from it, derives the encryption key ke, decrypts the secondary wrapped data (responder auth tag) into secondary[512], computes I-auth / R-auth (create_auth_tags) and the operating channel;
 * ctx->enrollee_status = RESPONDER_STATUS_OK on success, RESPONDER_STATUS_AUTH_FAILURE on the failure paths; returns RETURN_OK / RETURN_ERR.
 *
 * Scaffolding only: OpenSSL and AES-SIV are the real libraries; the callees get_tlv (wifi_tlv.c, with the shared bounds fix 3 = finding #205, not recounted), print_hex_dump, print_bignum, print_ec_point,
 * hkdf, get_auth_frame_wrapped_data, compute_key_hash, compute_encryption_key, compute_intermediate_key, create_auth_tags and channel_to_frequency are verbatim support code; wifi_getRadioChannel is a stub
 * (channel 6); wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppProcessAuthResponse.
 */
#include "hwr_wap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/crypto.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppProcessAuthResponse hwr_sg_wifi_dppProcessAuthResponse
/* support-code callees are renamed hwr_wap_<name> so they do not clash with the copies of other harnesses */
#define get_tlv hwr_wap_get_tlv
#define print_hex_dump hwr_wap_print_hex_dump
#define print_bignum hwr_wap_print_bignum
#define print_ec_point hwr_wap_print_ec_point
#define hkdf hwr_wap_hkdf
#define get_auth_frame_wrapped_data hwr_wap_get_auth_frame_wrapped_data
#define compute_key_hash hwr_wap_compute_key_hash
#define compute_encryption_key hwr_wap_compute_encryption_key
#define compute_intermediate_key hwr_wap_compute_intermediate_key
#define create_auth_tags hwr_wap_create_auth_tags
#define channel_to_frequency hwr_wap_channel_to_frequency
#define wifi_getRadioChannel hwr_wap_getRadioChannel
static int hwr_wap_getRadioChannel(int radioIndex, unsigned long *channel) { (void)radioIndex; *channel = 6; return 0; }

extern "C" {
/* --- wifi_tlv.c:29-46 (verbatim, support code: get_tlv) --- */
wifi_tlv_t *get_tlv(unsigned char *buff, unsigned short attrib, unsigned short len)
{
    unsigned int total_len = 0;
    bool found = false;
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    /* ---------- start fix 3: the attribute header (4 bytes) and the attribute value must lie inside the len bytes of the frame: a truncated header, or a length field larger than what is left,
       made the walk (and the callers' memcpy / BN_bin2bn / siv_decrypt on tlv->value) read past the frame buffer. */
    while (total_len + 2*sizeof(unsigned short) <= len) {
        if (tlv->type == attrib) {
            if (total_len + 2*sizeof(unsigned short) + tlv->length <= len) {
                found = true;
            }
            break;
        }

        total_len += (2*sizeof(unsigned short) + tlv->length);
        tlv = (wifi_tlv_t *)((unsigned char *)tlv + 2*sizeof(unsigned short) + tlv->length);
    }
    /* ---------- end fix 3 */

    return (found == true) ? tlv:NULL;
}

/* --- wifi_hal_dpp.c:755-788 (verbatim, support code: print_hex_dump) --- */
void print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

/* --- wifi_hal_dpp.c:789-804 (verbatim, support code: print_bignum) --- */

void
print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    print_hex_dump(len, buf);
    free(buf);
}

/* --- wifi_hal_dpp.c:839-968 (verbatim, support code: hkdf) --- */
int
hkdf (const EVP_MD *h, int skip,
      unsigned char *ikm, int ikmlen,
      unsigned char *salt, int saltlen,
      unsigned char *info, int infolen,
      unsigned char *okm, int okmlen)
{
    unsigned char *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
#endif

    digestlen = prklen = EVP_MD_size(h);
    if (digestlen == UINT_MAX) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        HMAC_CTX_free(ctx);
#endif
        return 0;
    }

    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
        perror("malloc");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        HMAC_CTX_free(ctx);
#endif
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(&ctx);
#else
    HMAC_CTX_reset(ctx);
#endif
    
    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = (unsigned char *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
            HMAC_CTX_free(ctx);
#endif
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (unsigned char *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
                HMAC_CTX_free(ctx);
#endif
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, digestlen);
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, infolen);
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
#endif
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}

/* --- wifi_hal_dpp.c:1065-1116 (verbatim, support code: get_auth_frame_wrapped_data) --- */
int
get_auth_frame_wrapped_data(wifi_dppPublicActionFrameBody_t *frame, unsigned int attrib_len, wifi_dpp_instance_t *instance, unsigned char *plain, unsigned int len, bool reconfig)
{
    siv_ctx ctx;
    wifi_tlv_t *tlv;
    unsigned int non_wrapped_len;;
	int decrypted_len;

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        printf("%s:%d: Could not find attribute in buffer\n", __func__, __LINE__);
        return -1;
    }
    printf("%s:%d: Key:\n", __func__, __LINE__);
    print_hex_dump(SHA512_DIGEST_LENGTH, (reconfig == false) ? instance->k2:instance->ke);
    printf("%s:%d: Cipher Text Length:%u\n", __func__, __LINE__, (unsigned int)tlv->length);
    printf("%s:%d: Cipher Text:\n", __func__, __LINE__);

    non_wrapped_len = (unsigned char *)tlv - frame->attrib;
    printf("%s:%d: Non wrapped length:%u, must match with %u attrib_len:%u\n", __func__, __LINE__,
        non_wrapped_len, (unsigned int)attrib_len - tlv->length, (unsigned int)attrib_len);

    if ((tlv->length < AES_BLOCK_SIZE) || ((tlv->length - AES_BLOCK_SIZE) > len)) {
        printf("%s:%d: Invalid wrapped data length:%u output capacity:%u\n",
            __func__, __LINE__, (unsigned int)tlv->length, len);
        return -1;
    }

    print_hex_dump(tlv->length, tlv->value);
    decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, tlv->value, 2,
                        frame, sizeof(wifi_dppPublicActionFrameBody_t),
                        frame->attrib, non_wrapped_len);
        
    printf("%s:%d: Decrypted length:%d\n", __func__, __LINE__, decrypted_len);


    return (decrypted_len == -1) ? -1:tlv->length - AES_BLOCK_SIZE;
}

/* --- wifi_hal_dpp.c:217-232 (verbatim, support code: channel_to_frequency) --- */
unsigned short channel_to_frequency(unsigned int channel)
{
    unsigned short frequency = 0;

    if (channel <= 14) {
        frequency = 2412 + 5*(channel - 1);
    } else if ((channel >= 36) && (channel <= 64)) {
        frequency = 5180 + 5*(channel - 36);
    } else if ((channel >= 100) && (channel <= 140)) {
        frequency = 5500 + 5*(channel - 100);
    } else if ((channel >= 149) && (channel <= 165)) {
        frequency = 5745 + 5*(channel - 149);
    }

    return frequency;
}

/* --- wifi_hal_dpp.c:806-837 (verbatim, support code: print_ec_point) --- */
void
print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

     if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }
        
    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}

/* --- wifi_hal_dpp.c:970-1020 (verbatim, support code: compute_key_hash) --- */
static int
compute_key_hash (EC_KEY *key, unsigned char *digest)
{
    int asn1len;
    BIO *bio;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ctx;
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
#endif
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        EVP_MD_CTX_free(ctx);
#endif
        return -1;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_init(&ctx);
#else
    EVP_MD_CTX_reset(ctx);
#endif
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, asn1, asn1len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, asn1, asn1len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    BIO_free(bio);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(&ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif
    return mdlen;
}

/* --- wifi_hal_dpp.c:1249-1285 (verbatim, support code: compute_encryption_key) --- */
int compute_encryption_key(wifi_dpp_instance_t *instance)
{
    unsigned int offset, primelen, bignums;
    unsigned char ikm[1024], *ptr;
    unsigned char salt[SHA512_DIGEST_LENGTH];

    memset(ikm, 0, 1024);
    primelen = BN_num_bytes(instance->prime);

    ptr = ikm;
    offset = primelen - BN_num_bytes(instance->m);
    BN_bn2bin(instance->m, ptr + offset);

    ptr += primelen;
    offset = primelen - BN_num_bytes(instance->n);
    BN_bn2bin(instance->n, ptr + offset);

    ptr += primelen;
    if (instance->mutual == true) {
        bignums = 3;
        offset = primelen - BN_num_bytes(instance->l);
        BN_bn2bin(instance->l, ptr + offset);
    } else {
        bignums = 2;
    }
 
    memcpy(salt, instance->initiator_nonce, instance->noncelen);
    memcpy(&salt[instance->noncelen], instance->responder_nonce, instance->noncelen);
    
    hkdf(instance->hashfcn, 0, ikm, bignums*primelen, salt, 2*instance->noncelen,
             (unsigned char *)"DPP Key", strlen("DPP Key"), instance->ke, instance->digestlen);

    printf("Encryption Key: ");
    print_hex_dump(instance->digestlen, instance->ke);

    return 0;
}

/* --- wifi_hal_dpp.c:1287-1312 (verbatim, support code: compute_intermediate_key) --- */
int    compute_intermediate_key(wifi_dpp_instance_t *instance, bool first)
{
    unsigned int primelen, offset, keylen;
    unsigned char m[2048];

	BIGNUM *x = (first == true)?instance->m:instance->n;
	const char *info = (first == true)?"first intermediate key":"second intermediate key";
	unsigned char *key = (first == true)?instance->k1:instance->k2;
    
    primelen = BN_num_bytes(instance->prime);
    
    memset(m, 0, primelen);
    offset = primelen - BN_num_bytes(x);
    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(instance->hashfcn, 0, m, primelen, NULL, 0, 
             (unsigned char *)info, strlen(info),
             key, instance->digestlen)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n");
    print_hex_dump(instance->digestlen, key);
    
    return 0;
}

/* --- wifi_hal_dpp.c:1314-1583 (verbatim, support code: create_auth_tags) --- */
int create_auth_tags    (wifi_dpp_instance_t *instance, char *iPubKeyInfoB64, char *rPubKeyInfoB64)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ictx, rctx;
#else
    EVP_MD_CTX *ictx = EVP_MD_CTX_new();
    EVP_MD_CTX *rctx = EVP_MD_CTX_new();
#endif
    unsigned char final;
    unsigned int offset = 0, primelen = 0, mdlen = 0;
    EC_POINT *pub, *rpt;
    unsigned char keyasn1[1024];
    unsigned char tag[SHA512_DIGEST_LENGTH];
    const unsigned char *key;
    int asn1len;
    EC_KEY *responder_boot_key, *initiator_boot_key;

    //I-auth’ = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1) 
    //R-auth’ = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0) 

    memset(instance->rauth, 0, SHA512_DIGEST_LENGTH);
    memset(instance->iauth, 0, SHA512_DIGEST_LENGTH);
    memset(tag, 0, SHA512_DIGEST_LENGTH);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ictx, instance->hashfcn);
    EVP_DigestInit(&rctx, instance->hashfcn);

    // nonces for I-auth
    EVP_DigestUpdate(&ictx, instance->responder_nonce, instance->noncelen);
    EVP_DigestUpdate(&ictx, instance->initiator_nonce, instance->noncelen);
     
    // nonces for R-auth
    EVP_DigestUpdate(&rctx, instance->initiator_nonce, instance->noncelen);
    EVP_DigestUpdate(&rctx, instance->responder_nonce, instance->noncelen);
#else
    EVP_DigestInit(ictx, instance->hashfcn);
    EVP_DigestInit(rctx, instance->hashfcn);

    // nonces for I-auth
    EVP_DigestUpdate(ictx, instance->responder_nonce, instance->noncelen);
    EVP_DigestUpdate(ictx, instance->initiator_nonce, instance->noncelen);
     
    // nonces for R-auth
    EVP_DigestUpdate(rctx, instance->initiator_nonce, instance->noncelen);
    EVP_DigestUpdate(rctx, instance->responder_nonce, instance->noncelen);
#endif

    // protocol keys for I-auth
    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
        
    memset(tag, 0, primelen);
    primelen = BN_num_bytes(instance->prime);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    if ((pub = (EC_POINT*)EC_KEY_get0_public_key(instance->initiator_proto_key)) == NULL) {
        printf("%s:%d: Failed to get public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
        
    }
        
    if (EC_POINT_get_affine_coordinates_GFp(instance->group, pub, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
     }
        
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    // protocol keys for R-auth
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
        
    memset(tag, 0, primelen);
    primelen = BN_num_bytes(instance->prime);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    // boot keys for I-auth
    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)rPubKeyInfoB64, strlen(rPubKeyInfoB64))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    /* ---------- start fix 8: d2i_EC_PUBKEY returns NULL for a base64 text that is not a public key (EC_KEY_set_conv_form(NULL) crashed). */
    if (responder_boot_key == NULL) {
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
    /* ---------- end fix 8 */

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    if ((rpt = (EC_POINT*)EC_KEY_get0_public_key(responder_boot_key)) == NULL) { 
        printf("%s:%d: Failed to get responder boot key point\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        EC_KEY_free(responder_boot_key);   /* fix 9 */
        return RETURN_ERR;
    }

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, rpt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        EC_KEY_free(responder_boot_key);   /* fix 9 */
        return RETURN_ERR;

    }
    
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)iPubKeyInfoB64, strlen(iPubKeyInfoB64))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        EC_KEY_free(responder_boot_key);   /* fix 9 */
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    /* ---------- start fix 8: same for the initiator boot key. */
    if (initiator_boot_key == NULL) {
        EC_KEY_free(responder_boot_key);   /* fix 9 */
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
    /* ---------- end fix 8 */

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_free(initiator_boot_key);   /* fix 9: not used afterwards */

    if (instance->mutual == true) {
        memset(tag, 0, primelen);
        offset = primelen - BN_num_bytes(instance->x);
        BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_DigestUpdate(&ictx, tag, primelen);
#else
        EVP_DigestUpdate(ictx, tag, primelen);
#endif
    }

    // boot keys for R-auth
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, rpt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        EC_KEY_free(responder_boot_key);   /* fix 9 */
        return RETURN_ERR;

    }
   
    if (instance->mutual == true) { 
        memset(tag, 0, primelen);
        offset = primelen - BN_num_bytes(instance->x);
        BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_DigestUpdate(&rctx, tag, primelen);
#else
        EVP_DigestUpdate(rctx, tag, primelen);
#endif
    }


    // 1 for I-auth
    final = 1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, &final, 1);
#else
    EVP_DigestUpdate(ictx, &final, 1);
#endif
    mdlen = instance->digestlen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestFinal(&ictx, instance->iauth, &mdlen);
#else
    EVP_DigestFinal(ictx, instance->iauth, &mdlen);
#endif

    printf("%s:%d: I-auth:\n", __func__, __LINE__);
    print_hex_dump(mdlen, instance->iauth);

    // 0 for R-auth
    final = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, &final, 1);
#else
    EVP_DigestUpdate(rctx, &final, 1);
#endif
    mdlen = instance->digestlen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestFinal(&rctx, instance->rauth, &mdlen);
#else
    EVP_DigestFinal(rctx, instance->rauth, &mdlen);
#endif

    printf("%s:%d: R-auth:\n", __func__, __LINE__);
    print_hex_dump(mdlen, instance->rauth);

#if OPENSSL_VERSION_NUMBER > 0x10100000L    
    EVP_MD_CTX_free(ictx);
    EVP_MD_CTX_free(rctx);
#endif
    
    EC_KEY_free(responder_boot_key);   /* fix 9 */
    return RETURN_OK;
}

/* --- wifi_hal_dpp.c:2571-2837 --- */
INT wifi_dppProcessAuthResponse(wifi_device_dpp_context_t *dpp_ctx)
{
    unsigned char keyasn1[1024];
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    unsigned char *key;
    unsigned int attrib_len, primelen;
    int asn1len;
	int decrypted_len;
    siv_ctx ctx;
    unsigned char   primary[512];
    unsigned char   secondary[512];
    EC_KEY *responder_boot_key;
    BIGNUM  *pi;
    wifi_tlv_t *tlv = NULL;
    unsigned char status;
    ULONG channel;
   	wifi_dppPublicActionFrameBody_t  *frame;
	unsigned int len;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t *instance;

    /* ---------- start fix 1: a NULL context was dereferenced at once. */
    if (dpp_ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    data = &dpp_ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

    if ((instance == NULL) || (instance->x == NULL) || (instance->y == NULL)) {
        return RETURN_ERR;
    }

	frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
	len = dpp_ctx->received_frame.length; 

	/* ---------- start fix 2: a NULL frame pointer (get_tlv read attrib[0]) and a frame shorter than the 6-byte body (attrib_len = len - 6 wrapped) were not rejected. */
	if ((frame == NULL) || (len < sizeof(wifi_dppPublicActionFrameBody_t)) || ((len - sizeof(wifi_dppPublicActionFrameBody_t)) > USHRT_MAX)) {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
		return RETURN_ERR;
	}
	/* ---------- end fix 2 */

	attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_proto_version, attrib_len)) == NULL) {
        dpp_ctx->enrollee_version = 1;
        printf("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    } else if (tlv->length != sizeof(dpp_ctx->enrollee_version)) {
        printf("%s:%d invalid protocol version length=%u\n", __func__, __LINE__, (unsigned int)tlv->length);
        return RETURN_ERR;
    } else {
        memcpy((unsigned char *)&dpp_ctx->enrollee_version, (unsigned char *)tlv->value, tlv->length);
        printf("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    }

    tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_status, attrib_len);
    if (tlv != NULL) {
        if (tlv->length != sizeof(status)) {
            printf("%s:%d invalid status length=%u\n", __func__, __LINE__, (unsigned int)tlv->length);
            dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
            return RETURN_ERR;
        }
        status = *tlv->value;
    } else {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (status != WIFI_STATUS_OK) {
        // return authentication failure for now
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_boot_hash, attrib_len)) == NULL) {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.rPubKey,
            strlen(data->u.config_data.rPubKey))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, asn1len);
    /* ---------- start fix 3: d2i_EC_PUBKEY returns NULL for a base64 text that is not a public key (EC_KEY_set_conv_form(NULL) crashed). */
    if (responder_boot_key == NULL) {
        printf("%s:%d Failed to parse responder public key\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- end fix 3 */

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    /* ---------- start fix 9: the responder boot key was never freed (leaked on every call). */
    int hash_ret = compute_key_hash(responder_boot_key, keyhash);
    EC_KEY_free(responder_boot_key);
    /* ---------- end fix 9 */
    if (hash_ret < 1) {
        printf("%s:%d Computing responder bootstrap key hash failed\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("%s:%d: Comparing Responder boot hash\n", __func__, __LINE__);
    /* ---------- start fix 4: the boot hash is a full SHA-256 (32 bytes); memcmp(tlv->length) accepted a shorter prefix or an empty hash and read keyhash past its 64 bytes for longer ones. */
    if ((tlv->length != SHA256_DIGEST_LENGTH) || (memcmp(tlv->value, keyhash, tlv->length) != 0)) {
    /* ---------- end fix 4 */
        printf("%s:%d: Comparing Responder boot hash with recived hash failed\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_protocol_key, attrib_len)) == NULL) {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("%s:%d: Responder Protocol key\n", __func__, __LINE__);
    print_hex_dump(tlv->length, tlv->value);

    primelen = BN_num_bytes(instance->prime);
    printf("primelen: %d\n", primelen);

    instance->x = BN_bin2bn(tlv->value, primelen, instance->x);
    instance->y = BN_bin2bn(tlv->value + primelen, primelen, instance->y);
    printf("X: ");
    print_bignum(instance->x);
    printf("Y: ");
    print_bignum(instance->y);

    if (EC_POINT_set_affine_coordinates_GFp(instance->group, instance->responder_proto_pt,
        instance->x, instance->y, instance->bnctx) == 0) {
        printf("%s:%d: Failed to set coordinates\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (EC_POINT_is_on_curve(instance->group, instance->responder_proto_pt,
            instance->bnctx) == 0) {
        printf("%s:%d: Point is not on curve\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    pi = (BIGNUM*)EC_KEY_get0_private_key(instance->initiator_proto_key);
    if (pi == NULL) {
        printf("%s:%d Could not get initiator protocol private point\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }


    if (EC_POINT_mul(instance->group, instance->N, NULL,
            instance->responder_proto_pt, pi, instance->bnctx) == 0) {
        printf("%s:%d: Multiply error\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->N,
            instance->n, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Coordinates get failure\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    printf("Point N:\n");
    print_ec_point(instance->group, instance->bnctx, instance->N);

    if (compute_intermediate_key(instance, false) != 0) {
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((decrypted_len = get_auth_frame_wrapped_data(frame, attrib_len, instance, primary, 512, false)) == -1) {
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_nonce, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get responder nonce\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    /* ---------- start fix 5: the responder nonce is exactly noncelen bytes long (the message below prints noncelen); 0..32 bytes were accepted. */
    else if ((tlv->length != instance->noncelen) || (tlv->length > sizeof(instance->responder_nonce))) {
    /* ---------- end fix 5 */
        wifi_dpp_dbg_print("%s:%d: Invalid responder nonce length=%u\n",__func__, __LINE__, (unsigned int)tlv->length);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    printf("Responder nonce: ");
    print_hex_dump(tlv->length, tlv->value);
    memcpy(instance->responder_nonce, tlv->value, tlv->length);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_cap, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get responder capabilitie\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    printf("Responder capabilities: ");
    print_hex_dump(tlv->length, tlv->value);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_initiator_nonce, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get initiator nonce nonce\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- start fix 6: the initiator nonce of the response must be the one sent in the Authentication Request. */
    if ((tlv->length != instance->noncelen) || (CRYPTO_memcmp(tlv->value, instance->initiator_nonce, instance->noncelen) != 0)) {
        printf("%s:%d: Initiator nonce mismatch\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- end fix 6 */

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_initiator_boot_hash, attrib_len)) == NULL) {
        printf("%s:%d: Mutual authentication not required\n", __func__, __LINE__);
        instance->mutual = false;
    } else {
        printf("%s:%d: Initiator boot hash\n", __func__, __LINE__);
        print_hex_dump(tlv->length, tlv->value);
        instance->mutual = true;
    }

    compute_encryption_key(instance);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_wrapped_data, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;

        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;

        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;

        default:
            printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
			dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        	return RETURN_ERR;
    }
    if (tlv->length < AES_BLOCK_SIZE || (tlv->length - AES_BLOCK_SIZE) > sizeof(secondary)) {
        wifi_dpp_dbg_print("%s:%d invalid wrapped_data length=%u output capacity=%u\n", 
            __func__, __LINE__, (unsigned int)tlv->length, (unsigned int)sizeof(secondary));
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], secondary,
            tlv->length - AES_BLOCK_SIZE, tlv->value, 0) < 1) {
        printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    if ((tlv = get_tlv(secondary, wifi_dpp_attrib_id_responder_auth_tag, tlv->length - AES_BLOCK_SIZE)) == NULL) {
        printf("%s:%d: Failed to get responder tag from secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("Responder Auth Tag: ");
    print_hex_dump(tlv->length, tlv->value);

    if (create_auth_tags(instance, data->u.config_data.iPubKey, data->u.config_data.rPubKey) == RETURN_ERR) {
        printf("%s:%d: Failed to get create auth tags\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    /* ---------- start fix 7: the received responder auth tag was never compared with the R-auth the function computed. */
    if ((tlv->length != instance->digestlen) || (CRYPTO_memcmp(tlv->value, instance->rauth, instance->digestlen) != 0)) {
        printf("%s:%d: Responder auth tag mismatch\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- end fix 7 */

    // success, we should change the channel to current operating channel
    wifi_getRadioChannel(dpp_ctx->ap_index%2, &channel);
    data->channel = channel_to_frequency(channel);

	dpp_ctx->enrollee_status = RESPONDER_STATUS_OK;
    return RETURN_OK;
}
}

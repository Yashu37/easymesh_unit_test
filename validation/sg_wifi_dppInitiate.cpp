/*
 * HANDLER: wifi_dppInitiate (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:3253-3379 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-7 (start fix n / end fix n markers: 1-6 in the handler (6 = EC_KEY_free marked inline), 7 in the create_dpp_session_instance copy, config branch + unsupported curve).  It starts a DPP authentication (config session): it decodes the
 * responder / initiator bootstrap keys (rPubKey / iPubKey), creates the session instance (create_dpp_session_instance: initiator protocol key, nonce, group, M and m), derives k1 (compute_intermediate_key),
 * builds the Authentication Request (initiator / responder boot key hashes, protocol version for version 2, initiator protocol key x || y, channel attribute of the radio's home channel, wrapped data = AES-SIV
 * with k1 of the initiator nonce / capabilities) and sends it with wifi_sendActionFrame on the frequency of the session channel; state = STATE_DPP_AUTH_RSP_PENDING.
 *
 * Scaffolding only: OpenSSL / AES-SIV are the real libraries; the callees set_tlv (wifi_tlv.c:49-58), channel_to_frequency (wifi_hal_dpp.c:217-232), freq_to_channel (wifi_hal_dpp.c:240-353), print_hex_dump (wifi_hal_dpp.c:755-788), print_bignum (wifi_hal_dpp.c:790-804), print_ec_point (wifi_hal_dpp.c:806-837), hkdf (wifi_hal_dpp.c:839-968), compute_key_hash (wifi_hal_dpp.c:970-1020), compute_intermediate_key (wifi_hal_dpp.c:1287-1312), set_auth_frame_wrapped_data (wifi_hal_dpp.c:1165-1220), create_dpp_session_instance (wifi_hal_dpp.c:1968-2159) are verbatim support code; wifi_sendActionFrame is a recording mock and wifi_getRadioChannel returns the case's home channel;
 * wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppInitiate.
 */
#include "hwr_wit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/rand.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
hwr_wit_cap_t hwr_wit_cap;
unsigned long hwr_wit_home_channel;
#define wifi_dppInitiate hwr_sg_wifi_dppInitiate
/* support-code callees are renamed hwr_wit_<name> so they do not clash with the copies of other harnesses */
#define set_tlv hwr_wit_set_tlv
#define channel_to_frequency hwr_wit_channel_to_frequency
#define freq_to_channel hwr_wit_freq_to_channel
#define print_hex_dump hwr_wit_print_hex_dump
#define print_bignum hwr_wit_print_bignum
#define print_ec_point hwr_wit_print_ec_point
#define hkdf hwr_wit_hkdf
#define compute_key_hash hwr_wit_compute_key_hash
#define compute_intermediate_key hwr_wit_compute_intermediate_key
#define set_auth_frame_wrapped_data hwr_wit_set_auth_frame_wrapped_data
#define create_dpp_session_instance hwr_wit_create_dpp_session_instance
#define wifi_sendActionFrame hwr_wit_sendActionFrame
#define wifi_getRadioChannel hwr_wit_getRadioChannel

extern "C" {
/* wifi_sendActionFrame mock: records the call */
INT hwr_wit_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency, UCHAR *frame, UINT len)
{
    hwr_wit_cap.calls++;
    hwr_wit_cap.ap = apIndex; memcpy(hwr_wit_cap.sta, sta, 6); hwr_wit_cap.freq = frequency; hwr_wit_cap.len = len;
    memcpy(hwr_wit_cap.frame, frame, len < sizeof(hwr_wit_cap.frame) ? len : sizeof(hwr_wit_cap.frame));
    return 0;
}
/* wifi_getRadioChannel mock: the home channel of the case */
INT hwr_wit_getRadioChannel(INT radioIndex, ULONG *channel) { (void)radioIndex; *channel = hwr_wit_home_channel; return 0; }

/* --- wifi_tlv.c:49-58 (verbatim, support code: set_tlv) --- */
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
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

/* --- wifi_hal_dpp.c:240-353 (verbatim, support code: freq_to_channel) --- */
unsigned short freq_to_channel(unsigned int freq)
{
    unsigned int temp = 0;
    int sec_channel = -1;
    unsigned int op_class = 0;
    if(freq)
    {
        if (freq >= 2412 && freq <= 2472)
        {
            if (sec_channel == 1)
                op_class = 83;
            else if (sec_channel == -1)
                op_class = 84;
            else
                op_class = 81;

            temp = ((freq - 2407) / 5);
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

        /** In Japan, 100 MHz of spectrum from 4900 MHz to 5000 MHz 
            can be used for both indoor and outdoor connection
         */
        if (freq >= 4900 && freq < 5000) 
        {
            if ((freq - 4000) % 5)
                return 0;
            temp = (freq - 4000) / 5;
            op_class = 0; /* TODO */
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        if (freq == 2484) 
        {
            op_class = 82; /* channel 14 */
            temp = 14;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 36..48 */
        if (freq >= 5180 && freq <= 5240) 
        {
            if ((freq - 5000) % 5)
                return 0;
 
            if (sec_channel == 1)
                op_class = 116;
            else if (sec_channel == -1)
                op_class = 117;
            else 
                op_class = 115;
 
            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 52..64 */
        if (freq >= 5260 && freq <= 5320) 
        {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 119;
            else if (sec_channel == -1)
                op_class = 120;
            else 
                op_class = 118;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 100..140 */
        if (freq >= 5000 && freq <= 5700) 
        {
            if (sec_channel == 1)
                op_class = 122;
            else if (sec_channel == -1)
                op_class = 123;
            else 
                op_class = 121;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 149..169 */
        if (freq >= 5745 && freq <= 5845) 
        {
            if (sec_channel == 1)
                op_class = 126;
            else if (sec_channel == -1)
                op_class = 127;
            else if (freq <= 5805)
                op_class = 124;
            else
                op_class = 125;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(freq)) {
            if (freq == 5935) {
                temp = 2;
                op_class = 131;
            } else {
                temp = (freq - 5950) % 5;
                op_class = 131 + center_idx_to_bw_6ghz((freq - 5950) / 5);
            }
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
#endif
    }
    printf("error: No case for given Freq\n");
    return 0;
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

/* --- wifi_hal_dpp.c:790-804 (verbatim, support code: print_bignum) --- */
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

/* --- wifi_hal_dpp.c:1165-1220 (verbatim, support code: set_auth_frame_wrapped_data) --- */
int
set_auth_frame_wrapped_data(wifi_dppPublicActionFrameBody_t *frame, unsigned int non_wrapped_len, wifi_dpp_instance_t *instance, bool auth_init)
{   
    siv_ctx ctx;
    unsigned char plain[512];
    wifi_tlv_t *tlv;
    unsigned char caps = 2;
    unsigned int wrapped_len = 0;
    wifi_tlv_t *wrapped_tlv;
    unsigned char *key;

    key = (auth_init == true) ? instance->k1:instance->ke;
    
    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }
    

    tlv = (wifi_tlv_t *)plain;
   
    if (auth_init == true) { 
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
        wrapped_len += (4 + instance->noncelen);
    
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_cap, 1, &caps);
        wrapped_len += 5;
    } else {
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_auth_tag, instance->digestlen, instance->iauth);
        wrapped_len += (4 + instance->digestlen);

    }

    wrapped_tlv = (wifi_tlv_t *)(frame->attrib + non_wrapped_len);
    wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;
    wrapped_tlv->length = wrapped_len + AES_BLOCK_SIZE;
    
    siv_encrypt(&ctx, plain, &wrapped_tlv->value[AES_BLOCK_SIZE], wrapped_len, wrapped_tlv->value, 2,
                    frame, sizeof(wifi_dppPublicActionFrameBody_t), 
                    frame->attrib, non_wrapped_len);
    
    //printf("%s:%d: Plain text:\n", __func__, __LINE__);
    //print_hex_dump(noncelen, plain);
    
    return wrapped_len + AES_BLOCK_SIZE;
}

/* --- wifi_hal_dpp.c:1968-2159 (verbatim, support code: create_dpp_session_instance) --- */
wifi_dpp_session_data_t *create_dpp_session_instance(wifi_device_dpp_context_t *ctx)
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    wifi_dpp_session_data_t    *data = NULL;
    int asn1len;
    EC_KEY *responder_key, *initiator_key;
    const EC_POINT *ipt, *rpt = NULL;
    const BIGNUM *proto_priv;
	wifi_dpp_instance_t *instance;


	data = &ctx->session_data;

	if (data->instance != NULL) {
    	wifi_dpp_dbg_print("%s:%d Session already exists\n", __func__, __LINE__);
		return data;
	}

	instance = (wifi_dpp_instance_t *)malloc(sizeof(wifi_dpp_instance_t));
	data->instance = instance;

	if (data->session == wifi_dpp_session_type_config) {
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.rPubKey, strlen(data->u.config_data.rPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	/* ---------- start fix 7: the half initialised instance block stayed in data->instance (garbage pointers for a later cancel). */
        	free(instance);
        	data->instance = NULL;
        	/* ---------- end fix 7 */
        	return NULL;
    	}

    	key = keyasn1;
    	responder_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    	/* ---------- start fix 7: d2i_EC_PUBKEY returns NULL for text that is not a public key. */
    	if (responder_key == NULL) {
        	free(instance);
        	data->instance = NULL;
        	return NULL;
    	}
    	/* ---------- end fix 7 */

    	EC_KEY_set_conv_form(responder_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(responder_key, OPENSSL_EC_NAMED_CURVE);

    	// get the group from responder's boot strap key information
    	if ((instance->group = EC_KEY_get0_group(responder_key)) == NULL) {
        	printf("%s:%d Failed to get group from ec key\n", __func__, __LINE__);
        	return NULL;
    	}
    
		rpt = EC_KEY_get0_public_key(responder_key);
    	if (rpt == NULL) {
        	printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        	return NULL;
    	}
    
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.iPubKey, strlen(data->u.config_data.iPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	/* ---------- start fix 7 */
        	free(instance);
        	data->instance = NULL;
        	/* ---------- end fix 7 */
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    	/* ---------- start fix 7 */
    	if (initiator_key == NULL) {
        	free(instance);
        	data->instance = NULL;
        	return NULL;
    	}
    	/* ---------- end fix 7 */

    	EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

	} else if (data->session == wifi_dpp_session_type_reconfig) {
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.reconfig_data.iPubKey, strlen(data->u.reconfig_data.iPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    	EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

		instance->group = EC_KEY_get0_group(initiator_key);
		instance->responder_connector = EC_POINT_new(instance->group);
	}

    instance->x = BN_new();
    instance->y = BN_new();
    instance->m = BN_new();
    instance->n = BN_new();
    instance->prime = BN_new();
    instance->bnctx = BN_CTX_new();

    instance->responder_proto_pt = EC_POINT_new(instance->group);
    instance->nid = EC_GROUP_get_curve_name(instance->group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, instance->nid);
    switch (instance->nid) {
        case NID_X9_62_prime256v1:
            instance->group_num = 19;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        case NID_secp384r1:
            instance->group_num = 20;
            instance->digestlen = 48;
            instance->hashfcn = EVP_sha384();
            break;
        case NID_secp521r1:
            instance->group_num = 21;
            instance->digestlen = 64;
            instance->hashfcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            instance->group_num = 25;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        case NID_secp224r1:
            instance->group_num = 26;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, instance->nid);
            /* ---------- start fix 7: everything allocated so far and the instance block were left behind (partly uninitialised instance in data->instance). */
            EC_POINT_free(instance->responder_proto_pt);
            BN_CTX_free(instance->bnctx);
            BN_free(instance->prime); BN_free(instance->n); BN_free(instance->m); BN_free(instance->y); BN_free(instance->x);
            free(instance);
            data->instance = NULL;
            /* ---------- end fix 7 */
            return NULL;
    }

    instance->noncelen = instance->digestlen/2;

    //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, instance->group_num, instance->digestlen);

    instance->initiator_proto_key = EC_KEY_new_by_curve_name(instance->nid);
    if (instance->initiator_proto_key == NULL) {
        printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
        return NULL;
    }

    if (EC_KEY_generate_key(instance->initiator_proto_key) == 0) {
        printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
        return NULL;
    }

    ipt = EC_KEY_get0_public_key(instance->initiator_proto_key);
    if (ipt == NULL) {
        printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
        return NULL;
    }

    proto_priv = EC_KEY_get0_private_key(instance->initiator_proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
        return NULL;
    }

    if ((instance->N = EC_POINT_new(instance->group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return NULL;
    }


    if ((instance->M = EC_POINT_new(instance->group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return NULL;
    }


    if (EC_POINT_get_affine_coordinates_GFp(instance->group, ipt, instance->x,
            instance->y, instance->bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return NULL;
    }

	if (data->session == wifi_dpp_session_type_config) {

    	if (EC_POINT_mul(instance->group, instance->M, NULL, rpt, proto_priv, instance->bnctx) == 0) {
        	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	return NULL;
    	}

            
    	printf("Point M:\n");
    	print_ec_point(instance->group, instance->bnctx, instance->M);

    	if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->M,
            	instance->m, NULL, instance->bnctx) == 0) {
        	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	return NULL;

    	}
	}

    RAND_bytes(instance->initiator_nonce, instance->noncelen);
    if (EC_GROUP_get_curve_GFp(instance->group, instance->prime, NULL, NULL, 
            instance->bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return NULL;
    }


    return data;
}

/* --- wifi_hal_dpp.c:3253-3379 --- */
int
wifi_dppInitiate(wifi_device_dpp_context_t *ctx)
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    int asn1len;
    EC_KEY *responder_boot_key = NULL, *initiator_boot_key = NULL;   /* fix 6: initialised so that the early returns can free them */
    unsigned char buff[2048];
    unsigned int wrapped_len;
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    wifi_dppPublicActionFrame_t    *public_action_frame;
    wifi_tlv_t *tlv;
    unsigned short tlv_len, chann_attr;;
    unsigned char protocol_key_buff[1024];
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t	*instance;
    ULONG hm_channel = 0;
    ULONG ch_freq = 0;

    /* ---------- start fix 1: a NULL context was dereferenced (ctx->ap_index). */
    if (ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    wifi_dpp_dbg_print("%s:%d Enter\n", __func__, __LINE__);
    wifi_getRadioChannel(ctx->ap_index%2, &hm_channel);
    ctx->activation_status = ActStatus_In_Progress; 

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)ctx->session_data.u.config_data.rPubKey, strlen(ctx->session_data.u.config_data.rPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    /* ---------- start fix 2: d2i_EC_PUBKEY returns NULL for text that is not a public key (EC_KEY_set_conv_form(NULL) crashed). */
    if (responder_boot_key == NULL) {
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)ctx->session_data.u.config_data.iPubKey, strlen(ctx->session_data.u.config_data.iPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        EC_KEY_free(responder_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    /* ---------- start fix 2 */
    if (initiator_boot_key == NULL) {
        ctx->activation_status = ActStatus_Failed;
        EC_KEY_free(responder_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);

    data = create_dpp_session_instance(ctx);
    /* ---------- start fix 3: create_dpp_session_instance returns NULL when the session instance cannot be built (e.g. a curve it does not handle); data was dereferenced. */
    if (data == NULL) {
        ctx->activation_status = ActStatus_Failed;
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }
    /* ---------- end fix 3 */
	instance = (wifi_dpp_instance_t *)data->instance;
    
    if (compute_intermediate_key(instance, true) != 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d failed to generate key\n", __func__, __LINE__);
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff; 

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
	
   	public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE; 

    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_auth_req;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;

    if (compute_key_hash(initiator_boot_key, keyhash) < 1) {
        ctx->activation_status = ActStatus_Failed;
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_boot_hash, SHA256_DIGEST_LENGTH, keyhash);    
    tlv_len += (SHA256_DIGEST_LENGTH + 4);
    
    if (compute_key_hash(responder_boot_key, keyhash) < 1) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_boot_hash, SHA256_DIGEST_LENGTH, keyhash);    
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

	if (ctx->configurator_version > 1) {
		tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(ctx->configurator_version), &ctx->configurator_version);
    	tlv_len += (sizeof(ctx->configurator_version) + 4);
	}

    /* ---------- start fix 4: x and y are each right aligned in a prime-length field: the buffer was not cleared (stack garbage in the leading bytes) and y was placed with the length of x. */
    memset(protocol_key_buff, 0, 2*BN_num_bytes(instance->prime));
    BN_bn2bin((const BIGNUM *)instance->x, 
        &protocol_key_buff[BN_num_bytes(instance->prime) - BN_num_bytes(instance->x)]);
    BN_bn2bin((const BIGNUM *)instance->y, 
        &protocol_key_buff[2*BN_num_bytes(instance->prime) - BN_num_bytes(instance->y)]);
    /* ---------- end fix 4 */
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_protocol_key, 2*BN_num_bytes(instance->prime), protocol_key_buff);
    tlv_len += (2*BN_num_bytes(instance->prime) + 4);

    chann_attr = freq_to_channel(channel_to_frequency(hm_channel)); //channel attrib shall be home channel
    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_channel, sizeof(unsigned short), (unsigned char *)&chann_attr);
    tlv_len += 6;
    
    wrapped_len = set_auth_frame_wrapped_data(&public_action_frame->public_action_body, tlv_len, instance, true);
    if (wrapped_len == UINT_MAX) {
        printf("%s:%d: Failed to set wrapped data\n", __func__, __LINE__);
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }
    tlv_len += (wrapped_len + 4);

    //printf("\n\n");
    //printf("%s:%d: Frame buffer:\n", __func__, __LINE__);
    //print_hex_dump(tlv_len, buff);
    ch_freq = (unsigned long) channel_to_frequency(data->channel);
    /* ---------- start fix 5: a session channel without a frequency (unknown -> 0) or channel 0 (-> 2407 MHz, not a channel) was sent. */
    if ((ch_freq == 0) || (data->channel == 0)) {
        ctx->activation_status = ActStatus_Failed;
        EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
        return RETURN_ERR;
    }
    /* ---------- end fix 5 */
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, ch_freq/*data->channel*/, (unsigned char *)public_action_frame, sizeof(wifi_dppPublicActionFrame_t) + tlv_len);
    data->state = STATE_DPP_AUTH_RSP_PENDING;
        

    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    EC_KEY_free(responder_boot_key); EC_KEY_free(initiator_boot_key);   /* fix 6 */
    return RETURN_OK;
}
}

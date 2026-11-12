/*
 * HANDLER: wifi_dppReconfigInitiate (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:3168-3251 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-6 (start fix n / end fix n markers: 1, 2, 4, 6 in the handler, 3 in the create_dpp_session_instance copy, 5 in the connector builder copy); the connector builder copy also carries the shared leak fix (finding #239, not recounted, marked fix L there).  It starts a DPP reconfiguration: it creates the session
 * instance (create_dpp_session_instance: initiator protocol key, nonce, group from the initiator bootstrap key iPubKey), draws a random transaction id into reconfig_data.tran_id[dpp_init_retries], builds the
 * Reconfiguration Authentication Request (transaction id, protocol version, signed connector, initiator nonce) and sends it with wifi_sendActionFrame on the frequency of the session channel.
 *
 * Scaffolding only: OpenSSL / cJSON are the real libraries; the callees print_hex_dump (wifi_hal_dpp.c:755-788), print_bignum (790-804), set_tlv (wifi_tlv.c:49-58), base64urlencode (wifi_hal_dpp.c:141-160), channel_to_frequency (wifi_hal_dpp.c:217-232), print_ec_point (wifi_hal_dpp.c:806-837), dpp_build_connector (wifi_hal_dpp.c:517-665), create_dpp_session_instance (wifi_hal_dpp.c:1968-2159) are verbatim support code; wifi_sendActionFrame is a recording mock; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppReconfigInitiate.
 */
#include "hwr_wrz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
hwr_wrz_cap_t hwr_wrz_cap;
#define wifi_dppReconfigInitiate hwr_sg_wifi_dppReconfigInitiate
/* support-code callees are renamed hwr_wrz_<name> so they do not clash with the copies of other harnesses */
#define set_tlv hwr_wrz_set_tlv
#define base64urlencode hwr_wrz_base64urlencode
#define channel_to_frequency hwr_wrz_channel_to_frequency
#define print_ec_point hwr_wrz_print_ec_point
#define print_hex_dump hwr_wrz_print_hex_dump
#define print_bignum hwr_wrz_print_bignum
#define dpp_build_connector hwr_wrz_dpp_build_connector
#define create_dpp_session_instance hwr_wrz_create_dpp_session_instance
#define wifi_sendActionFrame hwr_wrz_sendActionFrame

extern "C" {
/* wifi_sendActionFrame mock: records the call */
INT hwr_wrz_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency, UCHAR *frame, UINT len)
{
    hwr_wrz_cap.calls++;
    hwr_wrz_cap.ap = apIndex; memcpy(hwr_wrz_cap.sta, sta, 6); hwr_wrz_cap.freq = frequency; hwr_wrz_cap.len = len;
    memcpy(hwr_wrz_cap.frame, frame, len < sizeof(hwr_wrz_cap.frame) ? len : sizeof(hwr_wrz_cap.frame));
    return 0;
}

/* --- wifi_tlv.c:49-58 (verbatim, support code: set_tlv) --- */
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}

/* --- wifi_hal_dpp.c:141-160 (verbatim, support code: base64urlencode) --- */
int
base64urlencode (unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;
    printf("%s:%d: HERE\n", __func__, __LINE__);
    octets = EVP_EncodeBlock(burl, data, len);
    for (i = 0; i < octets; i++) {
        if (burl[i] == '+') {
            burl[i] = '-';
        } else if (burl[i] == '/') {
            burl[i] = '_';
        }
    }
    while (burl[octets-1] == '=') {
        burl[octets-1] = '\0';
        octets--;
    }
    printf("%s:%d: HERE EXIT\n", __func__, __LINE__);
    return octets;
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

/* --- wifi_hal_dpp.c:517-665 (verbatim, support code: dpp_build_connector) --- */
int dpp_build_connector(wifi_device_dpp_context_t *dpp_ctx, char* connector, bool responder)
{
#define BIGGEST_POSSIBLE_SIGNATURE      140
    wifi_dpp_reconfig_instance_t *recfg;
    wifi_dpp_csign_instance_t *sign;
    unsigned int bnlen, b64len, len, conn_len = 0, primelen = 0, siglen = 0, offset = 0;
    char buff[1024];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char sig[BIGGEST_POSSIBLE_SIGNATURE];
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX  ctx;
#else
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
#endif
    BIGNUM *x, *y;
    BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG *ecsig;
    /* ---------- start fix 5: base64url of a P-384 (48 bytes -> 64 chars + NUL) / P-521 (66 bytes -> 88 chars + NUL) coordinate overflowed the 64-byte buffers. */
    unsigned char b64x[2 * SHA512_DIGEST_LENGTH];
    unsigned char b64y[2 * SHA512_DIGEST_LENGTH];
    /* ---------- end fix 5 */
    unsigned char *bn;
    wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
    wifi_dpp_instance_t *instance = dpp_ctx->session_data.instance;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    recfg = (wifi_dpp_reconfig_instance_t *)obj->reconfigCtx;   
    sign = (wifi_dpp_csign_instance_t *)obj->cSignInstance;
    printf("%s:%d: recfg:%p sign:%p instance:%p\n", __func__, __LINE__, recfg, sign, instance);

    if ((sign == NULL) || recfg == NULL) {
        printf("%s:%d: reconfig context or csign instance does not exist, sign:%p recfg:%p\n", __func__, __LINE__, sign, recfg);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        EVP_MD_CTX_free(ctx);
#endif
        return -1;
    }

    bnlen = BN_num_bytes(instance->prime);
    printf("%s:%d: big number len:%d\n", __func__, __LINE__, bnlen);
    if (responder == false) {
        x = recfg->x;
        y = recfg->y;
    } else {
        if (!EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, instance->y, instance->bnctx)) {
            printf("%s:%d Could not get affine coordinates\n", __func__, __LINE__);
            return -1;
        }
        x = instance->x;
        y = instance->y;
    }

    printf("%s:%d: Here\n", __func__, __LINE__);
    bn = (unsigned char *)malloc(bnlen);
    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(x);
    BN_bn2bin(x, bn + offset);

    b64len = base64urlencode(b64x, bn, bnlen);
    b64x[b64len] = '\0';

    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(y);
    BN_bn2bin(y, bn + offset);
    b64len = base64urlencode(b64y, bn, bnlen);
    b64y[b64len] = '\0';

    free(bn);
    printf("%s:%d: Here\n", __func__, __LINE__);

    len = snprintf(buff, sizeof(buff), "{\"typ\":\"dppCon\",\"kid\":\"%s\",\"alg\":\"%s\"}",
            sign->kid, sign->alg);


    conn_len = base64urlencode(connector, (unsigned char *)buff, len);
    printf("%s:%d header:%s\n", __func__, __LINE__, buff);
    connector[conn_len++] = '.';

    len = snprintf(buff, sizeof(buff),
            "{\"groups\":[{\"groupId\":\"interop\",\"netRole\":\"%s\"}],"
            "\"netAccessKey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"},"
            "\"expiry\":\"2020-12-12T01:01:01\"}",
            (responder == false)?"configurator":"sta", b64x, b64y);

    conn_len += base64urlencode(connector + conn_len, buff, len);
    printf("%s:%d header and body:%s\n", __func__, __LINE__, buff);

    switch (EC_GROUP_get_curve_name(sign->group)) {
        case NID_X9_62_prime256v1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha256());
#else
            EVP_DigestInit(ctx, EVP_sha256());
#endif
            primelen = 32;
            break;
        case NID_secp384r1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha384());
#else
            EVP_DigestInit(ctx, EVP_sha384());
#endif
            primelen = 48;
            break;
        case NID_secp521r1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha512());
#else
            EVP_DigestInit(ctx, EVP_sha512());
#endif
            primelen = 66;
            break;
        default:
#if OPENSSL_VERSION_NUMBER > 0x10100000L
            EVP_MD_CTX_free(ctx);
#endif
            return -1;

    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ctx, connector, conn_len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestUpdate(ctx, connector, conn_len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    if ((ecsig = ECDSA_do_sign_ex(digest, mdlen, NULL, NULL, sign->key)) == NULL) {
        /* ---------- start fix L: shared with wifi_dppSendConfigResponse (finding #239, not recounted): EVP_MD_CTX and ECDSA_SIG were leaked. */
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        EVP_MD_CTX_free(ctx);
#endif
        /* ---------- end fix L */
        return -1;
    }
    ECDSA_SIG_get0(ecsig, (const BIGNUM **)&r, (const BIGNUM **)&s);

    memset(sig, 0, BIGGEST_POSSIBLE_SIGNATURE);
    offset = primelen - BN_num_bytes(r);
    BN_bn2bin(r, sig + offset);
    offset = primelen - BN_num_bytes(s);
    BN_bn2bin(s, sig + primelen + offset);
    siglen = primelen * 2;

    connector[conn_len++] = '.';
    conn_len += base64urlencode(connector + conn_len, sig, siglen);
    printf("%s:%d connector:%s\n", __func__, __LINE__, connector);

    /* ---------- start fix L */
    ECDSA_SIG_free(ecsig);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif
    /* ---------- end fix L */
    return conn_len;
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
        	return NULL;
    	}

    	key = keyasn1;
    	responder_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

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
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    	EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

	} else if (data->session == wifi_dpp_session_type_reconfig) {
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.reconfig_data.iPubKey, strlen(data->u.reconfig_data.iPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	/* ---------- start fix 3: the half initialised instance block stayed in data->instance (garbage pointers for a later cancel). */
        	free(instance);
        	data->instance = NULL;
        	/* ---------- end fix 3 */
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);
    	/* ---------- start fix 3: d2i_EC_PUBKEY returns NULL for text that is not a public key (EC_KEY_set_conv_form(NULL) crashed). */
    	if (initiator_key == NULL) {
        	printf("%s:%d Could not decode initiator public key\n", __func__, __LINE__);
        	free(instance);
        	data->instance = NULL;
        	return NULL;
    	}
    	/* ---------- end fix 3 */

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

/* --- wifi_hal_dpp.c:3168-3251 --- */
int
wifi_dppReconfigInitiate(wifi_device_dpp_context_t *ctx)
{
	unsigned char buff[2048];
	char 	reconfig_connector[1024];
	wifi_dppPublicActionFrame_t    *public_action_frame;
	ULONG ch_freq = 0;
	wifi_dpp_session_data_t    *data = NULL;
    wifi_tlv_t *tlv;
	unsigned short tlv_len;
	wifi_dpp_instance_t *instance;
	int conn_len = 0;
	wifi_dpp_configuration_object_t *obj = &ctx->config;

    /* ---------- start fix 1: a NULL context was dereferenced at once. */
    if (ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
	wifi_dpp_dbg_print("%s:%d Enter recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		obj->reconfigCtx, obj->cSignInstance);
    
    /* ---------- start fix 4: tran_id has 120 entries; dpp_init_retries >= 120 wrote tran_id[retries] outside the table (iPubKey[0] for 120, past the context for more). */
    if (ctx->dpp_init_retries >= sizeof(ctx->session_data.u.reconfig_data.tran_id)) {
        return RETURN_ERR;
    }
    /* ---------- end fix 4 */

	data = create_dpp_session_instance(ctx);
    /* ---------- start fix 2: create_dpp_session_instance returns NULL when the session instance cannot be built; data was dereferenced. */
    if (data == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */
	instance = (wifi_dpp_instance_t *)data->instance;
    int retry_cnt= ctx->dpp_init_retries;
	
	wifi_dpp_dbg_print("%s:%d Created session instance instance:%p recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		instance, obj->reconfigCtx, obj->cSignInstance);

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
    public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;
    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_recfg_auth_req;

	wifi_dpp_dbg_print("%s:%d Building TLVs instance:%p recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		instance, obj->reconfigCtx, obj->cSignInstance);


    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        (void)read(fd, &data->u.reconfig_data.tran_id[retry_cnt], sizeof(data->u.reconfig_data.tran_id[retry_cnt]));
        close(fd);
    }
	wifi_dpp_dbg_print("%s:%d Building TLV transaction id: %d \n", __func__, __LINE__,data->u.reconfig_data.tran_id[retry_cnt]);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_transaction_id, sizeof(unsigned char), &data->u.reconfig_data.tran_id[retry_cnt]);
    tlv_len += (sizeof(unsigned char) + 4);

	wifi_dpp_dbg_print("%s:%d Building TLV protocol version\n", __func__, __LINE__);
	tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(ctx->configurator_version), &ctx->configurator_version);
    tlv_len += (sizeof(ctx->configurator_version) + 4);
	
	memset(reconfig_connector, 0, 1024);
	if (dpp_build_connector(ctx, reconfig_connector, false) < 0) {
		return RETURN_ERR;
	}

	conn_len = strlen(reconfig_connector);
	wifi_dpp_dbg_print("%s:%d Building TLV connector\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_connector, conn_len, reconfig_connector);
	tlv_len += (conn_len + 4);

	wifi_dpp_dbg_print("%s:%d Building TLV nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
    tlv_len += (4 + instance->noncelen);
	
	wifi_dpp_dbg_print("%s:%d Building TLVs done\n", __func__, __LINE__);


    ch_freq = (unsigned long) channel_to_frequency(data->channel);
    /* ---------- start fix 6: a channel without a frequency (unknown -> 0) or channel 0 (-> 2407 MHz, not a channel) was sent. */
    if ((ch_freq == 0) || (data->channel == 0)) {
        return RETURN_ERR;
    }
    /* ---------- end fix 6 */
	wifi_dpp_dbg_print("%s:%d Trying sending frame on channel:%d\n", __func__, __LINE__, data->channel);

	wifi_sendActionFrame(ctx->ap_index, data->sta_mac, ch_freq, (unsigned char *)public_action_frame, sizeof(wifi_dppPublicActionFrame_t) + tlv_len);

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    return RETURN_OK;
}
}

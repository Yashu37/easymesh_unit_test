/*
 * HANDLER: wifi_dppProcessReconfigAuthResponse (src/wifi_hal_dpp.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-6; start fix n / end fix n markers, also in the get_tlv and dpp_build_point_from_connector_string support copies; the unfixed copy is the reproducer): src/wifi_hal_dpp.c:2180-2362 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-6.  It handles a received DPP Reconfiguration
 * Authentication Response frame: reads the transaction id (matched against the session's tran_id table), protocol version, connector (builds the responder connector point) and responder protocol key,
 * computes the reconfig key ke (HKDF over M = privkey * (responder_proto_pt + responder_connector)), decrypts the wrapped data with AES-SIV and checks the responder / initiator nonces.  It sets
 * enrollee_status = RESPONDER_STATUS_AUTH_FAILURE on the key / decrypt / nonce failure paths and returns RETURN_OK / RETURN_ERR.
 *
 * Scaffolding only: OpenSSL, cJSON and AES-SIV (hwr_wra_siv.o = util_crypto/aes_siv.c) are the real libraries; the callees get_tlv, base64urldecode, dpp_build_point_from_connector_string, print_hex_dump,
 * print_bignum, hkdf, get_auth_frame_wrapped_data and compute_reconfig_encryption_key are copied verbatim as support code; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to
 * a no-op sink; renamed hwr_sg_wifi_dppProcessReconfigAuthResponse.
 */
#include "hwr_wra.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppProcessReconfigAuthResponse hwr_sg_wifi_dppProcessReconfigAuthResponse
/* support-code callees are renamed hwr_wra_<name> so they do not clash with the copies of other harnesses */
#define get_tlv hwr_wra_get_tlv
#define base64urldecode hwr_wra_base64urldecode
#define dpp_build_point_from_connector_string hwr_wra_dpp_build_point_from_connector_string
#define print_hex_dump hwr_wra_print_hex_dump
#define print_bignum hwr_wra_print_bignum
#define hkdf hwr_wra_hkdf
#define get_auth_frame_wrapped_data hwr_wra_get_auth_frame_wrapped_data
#define compute_reconfig_encryption_key hwr_wra_compute_reconfig_encryption_key

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

/* --- wifi_hal_dpp.c:162-215 (verbatim, support code: base64urldecode) --- */
int
base64urldecode (unsigned char *data, unsigned char *burl, int len)
{
    int res, pad, i;
    unsigned char *b64, *unb64;

    if ((data == NULL) || (burl == NULL) || (len <= 0)) {
        return -1;
    }

    pad = 0;
    switch (len%4) {
        case 2:
            pad = 2;
            break;
        case 3:
            pad = 1;
            break;
        case 0:
            break;
        default:
            return -1;
    }
    if ((b64 = (unsigned char *)malloc(len + pad)) == NULL) {
        return -1;
    }
    if ((unb64 = (unsigned char *)malloc(len)) == NULL) {
        free(b64);
        return -1;
    }
    memset(b64, '=', len + pad);
    memcpy(b64, burl, len);

    for (i = 0; i < len; i++) {
        if (b64[i] == '-') {
            b64[i] = '+';
        } else if (b64[i] == '_') {
            b64[i] = '/';
        }
    }

    res = EVP_DecodeBlock(unb64, b64, len + pad);
    if (res == -1) {
        free(b64);
        free(unb64);
        return -1;
    }

    memcpy(data, unb64, res - pad);
    free(b64);
    free(unb64);

    return res - pad;
}

/* --- wifi_hal_dpp.c:418-514 (verbatim, support code: dpp_build_point_from_connector_string) --- */
EC_POINT *dpp_build_point_from_connector_string(wifi_device_dpp_context_t *ctx, const char *connector)
{
	cJSON *connector_json;
	const cJSON *netaccess_json;
	const cJSON *x_json, *y_json;
	unsigned char x[SHA512_DIGEST_LENGTH], y[SHA512_DIGEST_LENGTH]; 
	char connector_body[1024], connector_encoded[1024], *ptr;
	int len;
	wifi_dpp_instance_t *instance = ctx->session_data.instance;

	printf("%s:%d: Enter\n", __func__, __LINE__);

	if ((instance == NULL) || (instance->x == NULL) || (instance->y == NULL)) {
		return NULL;
	}

	if ((ptr = strchr(connector, '.')) == NULL) {
		printf("%s:%d: Wrong connector format\n", __func__, __LINE__);
		return NULL;	
	}

	ptr++;
	snprintf(connector_encoded, sizeof(connector_encoded), "%s", ptr);
	if ((ptr = strchr(connector_encoded, '.')) == NULL) {
		printf("%s:%d: Wrong connector format\n", __func__, __LINE__);
		return NULL;	
	}

	*ptr = 0;
	printf("%s:%d: enocded connector:%s\n", __func__, __LINE__, connector_encoded);

	len = base64urldecode((unsigned char *)connector_body, connector_encoded, strlen(connector_encoded));
    if (len == -1) {
        printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
        return NULL;
    }

	connector_json = cJSON_Parse(connector_body);
	if (connector_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		return NULL;
	}

	netaccess_json = cJSON_GetObjectItemCaseSensitive(connector_json, "netAccessKey");
	if (netaccess_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}	
	
	x_json = cJSON_GetObjectItemCaseSensitive(netaccess_json, "x");
	if (x_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}

	y_json = cJSON_GetObjectItemCaseSensitive(netaccess_json, "y");
	if (y_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}

	/* ---------- start fix 4: "x" / "y" must be json strings (a number / object has valuestring == NULL, strlen(NULL) crashed). */
	if (!cJSON_IsString(x_json) || (x_json->valuestring == NULL) || !cJSON_IsString(y_json) || (y_json->valuestring == NULL)) {
		printf("%s:%d: x or y is not a string\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}
	/* ---------- end fix 4 */
	/* ---------- start fix 5: x[] and y[] hold SHA512_DIGEST_LENGTH (64) bytes; base64urldecode copies the whole decoded value into them, a longer x / y overflowed the stack buffers. */
	if (((strlen(x_json->valuestring) * 3) / 4 > sizeof(x)) || ((strlen(y_json->valuestring) * 3) / 4 > sizeof(y))) {
		printf("%s:%d: x or y too long\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}
	/* ---------- end fix 5 */
	printf("%s:%d:X:%s\n", __func__, __LINE__, x_json->valuestring);
	printf("%s:%d:Y:%s\n", __func__, __LINE__, y_json->valuestring);

	len = base64urldecode(x, x_json->valuestring, strlen(x_json->valuestring));
	if (len == -1) {
		printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
        return NULL;
	}
	printf("%s:%d: base64 decoded x\n", __func__, __LINE__);

	instance->x = BN_bin2bn(x, len, instance->x);
	printf("%s:%d: Built big num x\n", __func__, __LINE__);

	len = base64urldecode(y, y_json->valuestring, strlen(y_json->valuestring));
	if (len == -1) {
		printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
        return NULL;
	}
	printf("%s:%d: base64 decoded y\n", __func__, __LINE__);

	instance->y = BN_bin2bn(y, len, instance->y);
	printf("%s:%d: Built big num y\n", __func__, __LINE__);

	EC_POINT_set_affine_coordinates_GFp(instance->group, instance->responder_connector, instance->x, instance->y, instance->bnctx);

	printf("%s:%d: point built\n", __func__, __LINE__);

       cJSON_Delete(connector_json);

	return instance->responder_connector;
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

/* --- wifi_hal_dpp.c:1222-1247 (verbatim, support code: compute_reconfig_encryption_key) --- */
int compute_reconfig_encryption_key(wifi_dpp_instance_t *instance)
{
    unsigned char m[2048];
    unsigned int primelen, offset;
    unsigned char salt[SHA512_DIGEST_LENGTH];

	if (!EC_POINT_get_affine_coordinates_GFp(instance->group, instance->M, instance->m, instance->n, instance->bnctx)) {
		printf("%s:%d Could not get affine coordinates\n", __func__, __LINE__);
        return -1;
	}
    primelen = BN_num_bytes(instance->prime);
    
    memset(m, 0, primelen);
    offset = primelen - BN_num_bytes(instance->m);
    BN_bn2bin(instance->m, m + offset);

    memcpy(salt, instance->initiator_nonce, instance->noncelen);
    
    hkdf(instance->hashfcn, 0, m, primelen, salt, instance->noncelen,
             (unsigned char *)"dpp reconfig key", strlen("dpp reconfig key"), instance->ke, instance->digestlen);

    printf("Encryption Key: \n");
    print_hex_dump(instance->digestlen, instance->ke);

	return 0;
}

/* --- wifi_hal_dpp.c:2180-2362 --- */
INT
wifi_dppProcessReconfigAuthResponse(wifi_device_dpp_context_t *dpp_ctx)
{
	unsigned char tran_id;
	wifi_tlv_t *tlv = NULL;
	char connector[1024];
	BIGNUM *priv_bn;
	unsigned char primary[512];
    wifi_dppPublicActionFrameBody_t  *frame;
    unsigned int len, attrib_len, primelen, decrypted_len;
    wifi_dpp_session_data_t *data = NULL;
    wifi_dpp_instance_t *instance;
	wifi_dpp_reconfig_instance_t *recfg;
	wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
    int i=0;

    wifi_dpp_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    /* ---------- start fix 1: a NULL context, a NULL reconfigCtx / reconfig key (dereferenced at EC_KEY_get0_private_key(recfg->key)) and a NULL frame were dereferenced. */
    if (dpp_ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    recfg = (wifi_dpp_reconfig_instance_t *)obj->reconfigCtx;
    /* ---------- start fix 1 (cont.) */
    if ((recfg == NULL) || (recfg->key == NULL)) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 (cont.) */

    data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    if ((instance == NULL) || (instance->x == NULL) || (instance->y == NULL)) {
        return RETURN_ERR;
    }

    frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
    len = dpp_ctx->received_frame.length;

    /* ---------- start fix 2: frame == NULL, or a frame shorter than the 6-byte action frame body, made attrib_len = len - 6 wrap to a huge value (get_tlv then walked far past the frame). */
    if ((frame == NULL) || (len < sizeof(wifi_dppPublicActionFrameBody_t)) ||
        ((len - sizeof(wifi_dppPublicActionFrameBody_t)) > USHRT_MAX)) {
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */
    attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_transaction_id, attrib_len)) == NULL) {
		return RETURN_ERR;
    } else if(tlv->length != sizeof(tran_id)) {
        wifi_dpp_dbg_print("%s:%d invalid transaction id len=%u\n",__func__, __LINE__, (unsigned int)tlv->length);
        return RETURN_ERR;
    } else {
        memcpy(&tran_id, (unsigned char *)tlv->value, tlv->length);
        for(i=(dpp_ctx->dpp_init_retries); i >= 0; i--){ 
            if (tran_id == data->u.reconfig_data.tran_id[i]){
            	wifi_dpp_dbg_print("%s:%d: transaction id match\n", __func__, __LINE__);
                data->u.reconfig_data.match_tran_id=tran_id;
                break;
            }
            if(i == 0){
                wifi_dpp_dbg_print("%s:%d: transaction id mismatch %d\n", __func__, __LINE__,tran_id);
                return RETURN_ERR;
            }
    	}
    }
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_proto_version, attrib_len)) == NULL) {
		return RETURN_ERR;
    } else if (tlv->length != sizeof(dpp_ctx->enrollee_version)) {
        wifi_dpp_dbg_print("%s:%d invalid protocol version length=%u\n", __func__, __LINE__, (unsigned int)tlv->length);
        return RETURN_ERR;
    } else {
        memcpy((unsigned char *)&dpp_ctx->enrollee_version, (unsigned char *)tlv->value, tlv->length);
        wifi_dpp_dbg_print("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_connector, attrib_len)) == NULL) {
		return RETURN_ERR;
    }

    if (tlv->length >= sizeof(connector)) {
        wifi_dpp_dbg_print("%s:%d invalid connector length=%u\n", __func__, __LINE__, (unsigned int)tlv->length);
        return RETURN_ERR;
    }

	memset(connector, 0, sizeof(connector));
    memcpy((unsigned char *)connector, (unsigned char *)tlv->value, tlv->length);
	
	if (dpp_build_point_from_connector_string(dpp_ctx, connector) == NULL) {
		wifi_dpp_dbg_print("%s:%d invalid connector\n", __func__, __LINE__);
		return RETURN_ERR;
	}

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_protocol_key, attrib_len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }


    wifi_dpp_dbg_print("%s:%d: Responder Protocol key\n", __func__, __LINE__);
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
        wifi_dpp_dbg_print("%s:%d: Failed to set coordinates\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (EC_POINT_is_on_curve(instance->group, instance->responder_proto_pt,
            instance->bnctx) == 0) {
        wifi_dpp_dbg_print("%s:%d: Point is not on curve\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    wifi_dpp_dbg_print("%s:%d: Computing key\n", __func__, __LINE__);

	// compute the Ke
	// M = c * (Cr + Pr)
	// ke = HKDF(I-nonce, "dpp reconfig key", M.x)
	
	EC_POINT_add(instance->group, instance->N, instance->responder_proto_pt, instance->responder_connector, instance->bnctx);

	priv_bn = (BIGNUM*)EC_KEY_get0_private_key(recfg->key);
	if (priv_bn == NULL) {
        printf("%s:%d: Failed to get priv key big number\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
	}
    wifi_dpp_dbg_print("%s:%d: EC point added\n", __func__, __LINE__);

	if (EC_POINT_mul(instance->group, instance->M, NULL, instance->N, priv_bn, instance->bnctx) == 0) {
    	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_dpp_dbg_print("%s:%d: EC point multiplied\n", __func__, __LINE__);
	compute_reconfig_encryption_key(instance);

    if ((decrypted_len = get_auth_frame_wrapped_data(frame, attrib_len, instance, primary, 512, true)) == -1) {
        wifi_dpp_dbg_print("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

	wifi_dpp_dbg_print("%s:%d: Decrypted length: %d\n", __func__, __LINE__, decrypted_len);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_nonce, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get responder nonce\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    /* ---------- start fix 6: the responder nonce is exactly noncelen bytes long (the message below already prints tlv->length / noncelen); a shorter nonce was accepted and copied. */
    if ((tlv->length != instance->noncelen) || (tlv->length > sizeof(instance->responder_nonce))) {
        wifi_dpp_dbg_print("%s:%d responder nonce length mismatch %u/%u\n", __func__, __LINE__,
            (unsigned int)tlv->length, (unsigned int)instance->noncelen);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- end fix 6 (responder nonce; the initiator nonce check below uses the same rule) */

    printf("Responder nonce: ");
    print_hex_dump(tlv->length, tlv->value);
    memcpy(instance->responder_nonce, tlv->value, tlv->length);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_cap, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get responder capabilitie\n", __func__, __LINE__);
    } else {
        wifi_dpp_dbg_print("Responder capabilities: ");
        print_hex_dump(tlv->length, tlv->value);
    }


    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_initiator_nonce, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get initiator nonce nonce\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    } else if ((tlv->length != instance->noncelen) || (tlv->length > sizeof(instance->initiator_nonce))) {
        wifi_dpp_dbg_print("%s:%d: initiator nonce length invalid\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    } else if (memcmp(tlv->value, instance->initiator_nonce, tlv->length) != 0) {
        wifi_dpp_dbg_print("%s:%d: initiator nonce mismatch\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    return RETURN_OK;
}
}

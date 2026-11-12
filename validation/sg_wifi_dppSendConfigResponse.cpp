/*
 * HANDLER: wifi_dppSendConfigResponse (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from fixes 1-6: start fix n / end fix n markers; the unfixed copy is the reproducer; fixes 3-6 sit in the support copies dpp_build_config / dpp_build_connector) from rdk-wifi-hal: src/wifi_hal_dpp.c:2865-2929 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-6.  It builds the DPP Configuration Response GAS frame
 * for the enrollee (status TLV + wrapped data = AES-SIV (key instance->ke, AAD = the status TLV) of the enrollee nonce and the configuration object JSON built by dpp_build_config), sends it with
 * wifi_sendActionFrame(ap_index, sta_mac, channel, frame, len) and returns RETURN_OK; RETURN_ERR (activation_status = ActStatus_Failed) when the wrapped data cannot be built.
 *
 * Scaffolding only: OpenSSL / cJSON / AES-SIV are the real libraries; the callees set_tlv (wifi_tlv.c:49-58), base64urlencode (141-160), dpp_build_csign_object (373-416), dpp_build_connector (517-665),
 * dpp_build_config (667-753) and set_config_frame_wrapped_data (1118-1163) are verbatim support code; wifi_sendActionFrame is a recording mock; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print,
 * here that goes to a no-op sink; renamed hwr_sg_wifi_dppSendConfigResponse.
 */
#include "hwr_wsc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
hwr_wsc_cap_t hwr_wsc_cap;
#define wifi_dppSendConfigResponse hwr_sg_wifi_dppSendConfigResponse
/* support-code callees are renamed hwr_wsc_<name> so they do not clash with the copies of other harnesses */
#define set_tlv hwr_wsc_set_tlv
#define base64urlencode hwr_wsc_base64urlencode
#define dpp_build_csign_object hwr_wsc_dpp_build_csign_object
#define dpp_build_connector hwr_wsc_dpp_build_connector
#define dpp_build_config hwr_wsc_dpp_build_config
#define set_config_frame_wrapped_data hwr_wsc_set_config_frame_wrapped_data
#define wifi_sendActionFrame hwr_wsc_sendActionFrame

extern "C" {
/* wifi_sendActionFrame mock: records the call */
INT hwr_wsc_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency, UCHAR *frame, UINT len)
{
    hwr_wsc_cap.calls++;
    hwr_wsc_cap.ap = apIndex; memcpy(hwr_wsc_cap.sta, sta, 6); hwr_wsc_cap.freq = frequency; hwr_wsc_cap.len = len;
    memcpy(hwr_wsc_cap.frame, frame, len < sizeof(hwr_wsc_cap.frame) ? len : sizeof(hwr_wsc_cap.frame));
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

/* --- wifi_hal_dpp.c:373-416 (verbatim, support code: dpp_build_csign_object) --- */
int dpp_build_csign_object(wifi_device_dpp_context_t *dpp_ctx, cJSON* csign)
{
	unsigned int b64len, bnlen, offset;
	unsigned char b64x[SHA512_DIGEST_LENGTH];
	unsigned char b64y[SHA512_DIGEST_LENGTH];
	unsigned char *bn;
	wifi_dpp_csign_instance_t *sign;
	wifi_dpp_instance_t *instance = dpp_ctx->session_data.instance;
	wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
	
	sign = obj->cSignInstance;

	if (sign == NULL) {
		printf("%s:%d sign does not exist\n", __func__, __LINE__);
		return -1;
	}

    bnlen = BN_num_bytes(instance->prime);
	printf("%s:%d: big number len:%d\n", __func__, __LINE__, bnlen);
    bn = (unsigned char *)malloc(bnlen);
    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(sign->x);
    BN_bn2bin(sign->x, bn + offset);

    b64len = base64urlencode(b64x, bn, bnlen);
    b64x[b64len] = '\0';

    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(sign->y);
    BN_bn2bin(sign->y, bn + offset);
    b64len = base64urlencode(b64y, bn, bnlen);
    b64y[b64len] = '\0';

	free(bn);
			
	cJSON_AddStringToObject(csign, "kty", "EC");
	cJSON_AddStringToObject(csign, "crv", "P-256");
	cJSON_AddStringToObject(csign, "x", b64x);
	cJSON_AddStringToObject(csign, "y", b64y);
	cJSON_AddStringToObject(csign, "kid", sign->kid);

	return 0;

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
    unsigned char b64x[SHA512_DIGEST_LENGTH];
    unsigned char b64y[SHA512_DIGEST_LENGTH];
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
        /* ---------- start fix 6: EVP_MD_CTX and ECDSA_SIG were leaked on the success path (and the context on this failure). */
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        EVP_MD_CTX_free(ctx);
#endif
        /* ---------- end fix 6 */
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

    /* ---------- start fix 6 */
    ECDSA_SIG_free(ecsig);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif
    /* ---------- end fix 6 */
    return conn_len;
}

/* --- wifi_hal_dpp.c:667-753 (verbatim, support code: dpp_build_config) --- */
void dpp_build_config(wifi_device_dpp_context_t *ctx, char* str)
{
 	char *out;
	char reconfig_connector[1024];
	wifi_dpp_configuration_object_t *obj = &ctx->config;

	/*No Array, Root only*/
    cJSON *root;
	/*Objects: discovery, cred, csign*/
	cJSON *discovery, *cred, *csign;


	memset(reconfig_connector, 0, 1024);
    printf("%s:%d: HERE ctx->enrollee_version = %d\n", __func__, __LINE__, ctx->enrollee_version);
    if(ctx->enrollee_version == 2)
        dpp_build_connector(ctx, reconfig_connector, true);

    /* check for enrollee_version and keyManagement */
    /* for enrollee_version=1, keyManagement must be *_MGMT_PSK*/
    if((ctx->enrollee_version == 1) && (obj->credentials.keyManagement != WIFI_DPP_KEY_MGMT_PSK)) {
        obj->credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
        printf("mismatch between enrollee_version & keyManagement, hence Now key  = %d\n", obj->credentials.keyManagement);
    }
    root  = cJSON_CreateObject();

	switch(obj->wifiTech)
	{
		case WIFI_DPP_TECH_INFRA:
		cJSON_AddItemToObject(root, "wi-fi_tech", cJSON_CreateString("infra"));
		break;
		default:
		break;
	}

	/*discovery: ssid*/
	cJSON_AddItemToObject(root, "discovery", discovery = cJSON_CreateObject());
	if (obj->discovery[0] != '\0') {
		/* ---------- start fix 4: discovery is char[32] without a terminator for a 32-character ssid; the string read ran into keyManagement. */
		char ssid_str[sizeof(obj->discovery) + 1];
		memcpy(ssid_str, obj->discovery, sizeof(obj->discovery));
		ssid_str[sizeof(obj->discovery)] = '\0';
		cJSON_AddStringToObject(discovery, "ssid", ssid_str);
		/* ---------- end fix 4 */
	}

	/*cred*/
	cJSON_AddItemToObject(root, "cred", cred = cJSON_CreateObject());

	switch(obj->credentials.keyManagement)
	{
		case WIFI_DPP_KEY_MGMT_PSK:
			cJSON_AddStringToObject(cred, "akm", "psk");
			cJSON_AddStringToObject(cred, "pass", obj->credentials.creds.passPhrase);
			break;

		case WIFI_DPP_KEY_MGMT_DPP:
			cJSON_AddStringToObject(cred, "akm", "dpp");
        	break;

		case WIFI_DPP_KEY_MGMT_SAE:
			cJSON_AddStringToObject(cred, "akm", "sae");
        	break;

		case WIFI_DPP_KEY_MGMT_PSKSAE:
			/* ---------- start fix 3: the akm was missing for PSK+SAE (empty cred object). */
			cJSON_AddStringToObject(cred, "akm", "psk+sae");
			cJSON_AddStringToObject(cred, "pass", obj->credentials.creds.passPhrase);
			/* ---------- end fix 3 */
			break;

		case WIFI_DPP_KEY_MGMT_DPPPSKSAE:
			cJSON_AddStringToObject(cred, "akm", "dpp+psk+sae");
			cJSON_AddStringToObject(cred, "pass", obj->credentials.creds.passPhrase);
			/*signedConnector*/
			cJSON_AddStringToObject(cred, "signedConnector", reconfig_connector);
			/*csign*/
			csign = cJSON_CreateObject();	
			dpp_build_csign_object(ctx, csign);

			cJSON_AddItemToObject(cred, "csign", csign);
			break;

		default:
			break;
	}

	out = cJSON_Print(root);
        if (out)
        {
            printf("%s\n",out);
            /*let input string have json */
            strcpy(str, out);
            free(out);
        }

	/* ---------- start fix 5: the cJSON tree was never freed (leaked on every call). */
	cJSON_Delete(root);
	/* ---------- end fix 5 */
	return;
}

/* --- wifi_hal_dpp.c:1118-1163 (verbatim, support code: set_config_frame_wrapped_data) --- */
int
set_config_frame_wrapped_data(unsigned char *ptr, unsigned int non_wrapped_len, wifi_dpp_instance_t *instance, wifi_device_dpp_context_t *dpp_ctx)
{
    siv_ctx ctx;
    unsigned char plain[2048];
    wifi_tlv_t *tlv;
    unsigned int wrapped_len = 0;
    wifi_tlv_t *wrapped_tlv;
	char json[1024];

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
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    tlv = (wifi_tlv_t *)plain;

    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_enrollee_nonce, instance->noncelen, instance->enrollee_nonce);
    wrapped_len += (4 + instance->noncelen);

    if (NULL != dpp_ctx) {
	    memset(json, 0, 1024);
	    dpp_build_config(dpp_ctx, json);
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_config_object, strlen(json), json);
        wrapped_len += (4 + strlen(json));
    }

    wrapped_tlv = (wifi_tlv_t *)(ptr + non_wrapped_len);
    wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;
    wrapped_tlv->length = wrapped_len + AES_BLOCK_SIZE;

    siv_encrypt(&ctx, plain, &wrapped_tlv->value[AES_BLOCK_SIZE], wrapped_len, wrapped_tlv->value, 1,
                    ptr, non_wrapped_len);

    return wrapped_len + AES_BLOCK_SIZE;
}

/* --- wifi_hal_dpp.c:2865-2929 --- */
INT wifi_dppSendConfigResponse(wifi_device_dpp_context_t *ctx) 
{
    wifi_dppConfigResponseFrame_t    *config_response_frame;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t *instance;
    unsigned char buff[2048], dpp_status = WIFI_STATUS_OK;
    wifi_tlv_t *tlv;
    unsigned int tlv_len = 0, wrapped_len = 0;

    /* ---------- start fix 1: a NULL context was dereferenced at once. */
    if (ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    printf("%s:%d: Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement %u\n", __func__, __LINE__, ctx->config.credentials.keyManagement);
   
    ctx->activation_status = ActStatus_In_Progress; 
    data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

    /* ---------- start fix 2: a NULL session instance was dereferenced (instance->digestlen) in set_config_frame_wrapped_data. */
    if (instance == NULL) {
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */

    config_response_frame = (wifi_dppConfigResponseFrame_t *)buff;

    config_response_frame->public_action_hdr.cat = 0x04;
    config_response_frame->public_action_hdr.action = 0x0b;
    config_response_frame->gas_resp_body.token = ctx->token; //add same token
    config_response_frame->gas_resp_body.status = 0;
    config_response_frame->gas_resp_body.comeback_delay = 0;
    config_response_frame->gas_resp_body.proto_elem.id = 0x6c;
    config_response_frame->gas_resp_body.proto_elem.len = 0x08;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.query_rsp_info = 0x7f;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.adv_proto_id = wifi_adv_proto_id_vendor_specific;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.len = sizeof(wifi_dppOUI) + 1;
	config_response_frame->dpp_oui.oui[0] = 0x50;
	config_response_frame->dpp_oui.oui[1] = 0x6f;
	config_response_frame->dpp_oui.oui[2] = 0x9a;

   	config_response_frame->dpp_oui.oui_type = DPP_OUI_TYPE;

    config_response_frame->dpp_proto = DPP_CONFPROTO;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)config_response_frame->rsp_body;

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &dpp_status);
    tlv_len += 5;

    wrapped_len = set_config_frame_wrapped_data(config_response_frame->rsp_body, tlv_len, instance, ctx);
    if (wrapped_len == UINT_MAX) {
        ctx->activation_status = ActStatus_Failed;
        printf("%s:%d Invalid wrapped_len\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    tlv_len += (wrapped_len + 4);

    config_response_frame->rsp_len = tlv_len;

    printf("%s:%d: Sending frame\n", __func__, __LINE__);
    printf("%s:%d: Sending frame freqency/channel:%u len:%u\n", __func__, __LINE__, data->channel, sizeof(wifi_dppConfigResponseFrame_t) + tlv_len);
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, data->channel, (unsigned char *)config_response_frame, 
                    sizeof(wifi_dppConfigResponseFrame_t) + tlv_len);

    printf("%s:%d: credentials.keyManagement %u\n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    printf("%s:%d Send Config Response success\n", __func__, __LINE__);

    return RETURN_OK;

}
}

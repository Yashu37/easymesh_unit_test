/*
 * HANDLER: wifi_dppSendAuthCnf (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:3040-3142 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It builds the DPP Authentication Confirm public action
 * frame (status TLV, [initiator boot hash,] responder boot hash = SHA-256 of the DER of the configured rPubKey / iPubKey, wrapped data = AES-SIV (key instance->ke, AAD = frame body + the attributes in front)
 * of the initiator auth tag instance->iauth), sends it with wifi_sendActionFrame(ap_index, sta_mac, session channel, frame, len), sets data->state = STATE_DPP_AUTHENTICATED and returns RETURN_OK;
 * the failure paths set activation_status = ActStatus_Failed and return RETURN_ERR.
 *
 * Scaffolding only: OpenSSL / AES-SIV are the real libraries; the callees set_tlv (wifi_tlv.c:49-58), compute_key_hash (970-1020) and set_auth_frame_wrapped_data (1165-1220) are verbatim support code;
 * wifi_sendActionFrame is a recording mock; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppSendAuthCnf.
 */
#include "hwr_wsu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
hwr_wsu_cap_t hwr_wsu_cap;
#define wifi_dppSendAuthCnf hwr_sg_wifi_dppSendAuthCnf
/* support-code callees are renamed hwr_wsu_<name> so they do not clash with the copies of other harnesses */
#define set_tlv hwr_wsu_set_tlv
#define compute_key_hash hwr_wsu_compute_key_hash
#define set_auth_frame_wrapped_data hwr_wsu_set_auth_frame_wrapped_data
#define wifi_sendActionFrame hwr_wsu_sendActionFrame

extern "C" {
/* wifi_sendActionFrame mock: records the call */
INT hwr_wsu_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency, UCHAR *frame, UINT len)
{
    hwr_wsu_cap.calls++;
    hwr_wsu_cap.ap = apIndex; memcpy(hwr_wsu_cap.sta, sta, 6); hwr_wsu_cap.freq = frequency; hwr_wsu_cap.len = len;
    memcpy(hwr_wsu_cap.frame, frame, len < sizeof(hwr_wsu_cap.frame) ? len : sizeof(hwr_wsu_cap.frame));
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

/* --- wifi_hal_dpp.c:3040-3142 --- */
int
wifi_dppSendAuthCnf(wifi_device_dpp_context_t *ctx)       
{
    unsigned char keyasn1[1024];
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    const unsigned char *key;
    unsigned char buff[2048], dpp_status = WIFI_STATUS_OK;
    unsigned int tlv_len = 0, wrapped_len = 0;
    int asn1len;
    wifi_dppPublicActionFrame_t    *public_action_frame;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t	*instance;
    EC_KEY *responder_boot_key, *initiator_boot_key;
    wifi_tlv_t *tlv;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    ctx->activation_status = ActStatus_In_Progress;

    data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, data->u.config_data.rPubKey, strlen(data->u.config_data.rPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, data->u.config_data.iPubKey, strlen(data->u.config_data.iPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;

   	public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;

    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_auth_cnf;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;
    
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &dpp_status);
    tlv_len += 5;

    if (instance->mutual == true) {

        if (compute_key_hash(initiator_boot_key, keyhash) < 1) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	ctx->activation_status = ActStatus_Failed;
            return RETURN_ERR;
        }

        tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_boot_hash, SHA256_DIGEST_LENGTH, keyhash);
        tlv_len += (SHA256_DIGEST_LENGTH + 4);
    }

    printf("%s:%d: Computing bootstrap key hash\n", __func__, __LINE__);
    if (compute_key_hash(responder_boot_key, keyhash) < 1) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_boot_hash, SHA256_DIGEST_LENGTH, keyhash);
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

    printf("%s:%d: Setting wrapped data\n", __func__, __LINE__);
    wrapped_len = set_auth_frame_wrapped_data(&public_action_frame->public_action_body, tlv_len, instance, false);
    if (wrapped_len == UINT_MAX) {
        printf("%s:%d: Failed to set wrapped data\n", __func__, __LINE__);
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }
    tlv_len += (wrapped_len + 4);

    printf("%s:%d: Sending frame\n", __func__, __LINE__);
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, data->channel, (unsigned char *)public_action_frame, 
            sizeof(wifi_dppPublicActionFrame_t) + tlv_len);

    data->state = STATE_DPP_AUTHENTICATED;
    printf("%s:%d Send Auth Confirmation success\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);

    return RETURN_OK;
}
}

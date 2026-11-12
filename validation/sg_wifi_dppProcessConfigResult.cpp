/*
 * HANDLER: wifi_dppProcessConfigResult (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:2392-2520 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It handles a received DPP Configuration Result
 * frame: finds the wrapped data attribute (attributes start after the 6-byte action frame body), decrypts it with AES-SIV using the session key ke (SIV_256 / 384 / 512 by digestlen), looks for the
 * DPP status attribute (1 byte) in the plaintext and sets dpp_ctx->enrollee_status (RESPONDER_STATUS_OK on status 0, RESPONDER_STATUS_CONFIGURATION_FAILURE otherwise) and returns RETURN_OK / RETURN_ERR.
 * The CONFIG_RESULT_SIMULATE block is never compiled (the macro is not defined anywhere in rdk-wifi-hal) and is kept as in the source.
 *
 * Scaffolding only: AES-SIV is the real library (hwr_wra_siv.o = util_crypto/aes_siv.c); the callee get_tlv (wifi_tlv.c, with the shared bounds fix 3 = finding #205 of wifi_dppProcessReconfigAuthResponse,
 * not recounted here) is support code; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppProcessConfigResult.
 */
#include "hwr_wcr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppProcessConfigResult hwr_sg_wifi_dppProcessConfigResult
/* support-code callees are renamed hwr_wcr_<name> so they do not clash with the copies of other harnesses */
#define get_tlv hwr_wcr_get_tlv

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

/* --- wifi_hal_dpp.c:2392-2520 --- */
INT
wifi_dppProcessConfigResult(wifi_device_dpp_context_t *dpp_ctx)
{
    unsigned int attrib_len;
	int decrypted_len;
    siv_ctx ctx;
    wifi_tlv_t *tlv = NULL;
    wifi_dppPublicActionFrameBody_t  *frame;
    unsigned int len;
    wifi_dpp_session_data_t *data = NULL;
    wifi_dpp_instance_t *instance;
    unsigned char plain[128], status;
#ifdef CONFIG_RESULT_SIMULATE
    unsigned int tlv_len = 0;
    unsigned char buff[256];
    wifi_tlv_t *wrapped_tlv;
#endif

    data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
    len = dpp_ctx->received_frame.length;

#ifdef CONFIG_RESULT_SIMULATE
	// temporarily simulate a buffer until encryption is fixed
	frame = (wifi_dppPublicActionFrameBody_t *)buff;
    frame->dpp_oui.oui[0] = 0x50;
    frame->dpp_oui.oui[1] = 0x6f;
    frame->dpp_oui.oui[2] = 0x9a;
    frame->dpp_oui.oui_type = DPP_OUI_TYPE;
    frame->crypto = 1;
    frame->frame_type = wifi_dpp_public_action_frame_type_cfg_result;
	wrapped_tlv = (wifi_tlv_t *)frame->attrib;
	wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;

	tlv = (wifi_tlv_t *)(&wrapped_tlv->value[AES_BLOCK_SIZE]);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &status);
	tlv_len += 5;
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_enrollee_nonce, instance->noncelen, instance->enrollee_nonce);
	tlv_len += (instance->noncelen + 4);
	print_hex_dump(tlv_len, &wrapped_tlv->value[AES_BLOCK_SIZE]);

	wrapped_tlv->length = tlv_len + AES_BLOCK_SIZE;
	len = sizeof(wifi_dppPublicActionFrameBody_t) + wrapped_tlv->length;
    
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
            dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
            return RETURN_ERR;
    }

    siv_encrypt(&ctx, &wrapped_tlv->value[AES_BLOCK_SIZE], &wrapped_tlv->value[AES_BLOCK_SIZE], tlv_len, wrapped_tlv->value, 1,
                    frame, sizeof(wifi_dppPublicActionFrameBody_t));

	print_hex_dump(len, frame);
#endif

    attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
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
            dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
            return RETURN_ERR;
    }

    if (tlv->length < AES_BLOCK_SIZE || (tlv->length - AES_BLOCK_SIZE) > sizeof(plain)) {
        wifi_dpp_dbg_print("%s:%d invalid wrapped_data length=%u output capacity=%u\n", 
            __func__, __LINE__, (unsigned int)tlv->length, (unsigned int)sizeof(plain));
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
        return RETURN_ERR;
    }
	if ((decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, 
							tlv->value, 1, frame, sizeof(wifi_dppPublicActionFrameBody_t))) < 0) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		return RETURN_ERR;
	}

	len = tlv->length - AES_BLOCK_SIZE;

    if ((tlv = get_tlv(plain, wifi_dpp_attrib_id_status, len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
		return RETURN_ERR;
    } else if (tlv->length != sizeof(status)) {
        wifi_dpp_dbg_print("%s:%d invalid status length=%u\n",__func__, __LINE__, (unsigned int)tlv->length);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
        return RETURN_ERR;
    }
	memcpy(&status, tlv->value, tlv->length);
	if (status != 0) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
		return RETURN_ERR;
	}
        
	dpp_ctx->enrollee_status = RESPONDER_STATUS_OK;

	return RETURN_OK;
}
}

/*
 * HANDLER: wifi_dppProcessConfigRequest (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:2522-2569 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It handles a received DPP Configuration Request
 * (the GAS payload attributes: received_frame.frame points at the first attribute and .length is the attribute length): decrypts the wrapped data attribute with AES-SIV (get_config_frame_wrapped_data,
 * key instance->ke, SIV_256 / 384 / 512 by digestlen, no associated data) into buff[1024], finds the enrollee nonce attribute in the plaintext, stores it in instance->enrollee_nonce (32 bytes) and sets
 * ctx->enrollee_status (RESPONDER_STATUS_OK, or RESPONDER_STATUS_AUTH_FAILURE on every failure), returning RETURN_OK / RETURN_ERR.
 *
 * Scaffolding only: AES-SIV is the real library (hwr_wra_siv.o = util_crypto/aes_siv.c); the callees get_tlv (wifi_tlv.c, with the shared bounds fix 3 = finding #205 of wifi_dppProcessReconfigAuthResponse,
 * not recounted here), print_hex_dump and get_config_frame_wrapped_data (1022-1063) are verbatim support code; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink;
 * renamed hwr_sg_wifi_dppProcessConfigRequest.
 */
#include "hwr_wcq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppProcessConfigRequest hwr_sg_wifi_dppProcessConfigRequest
/* support-code callees are renamed hwr_wcq_<name> so they do not clash with the copies of other harnesses */
#define get_tlv hwr_wcq_get_tlv
#define print_hex_dump hwr_wcq_print_hex_dump
#define get_config_frame_wrapped_data hwr_wcq_get_config_frame_wrapped_data

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

/* --- wifi_hal_dpp.c:1022-1063 (verbatim, support code: get_config_frame_wrapped_data) --- */
int
get_config_frame_wrapped_data(unsigned char *ptr, unsigned int attrib_len, wifi_dpp_instance_t *instance, unsigned char *plain, unsigned int len)
{
    siv_ctx ctx;
    wifi_tlv_t *tlv;
    int decrypted_len;

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

    if ((tlv = get_tlv(ptr, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        printf("%s:%d: Could not find attribute in buffer\n", __func__, __LINE__);
        return -1;
    }

    if (tlv->length < AES_BLOCK_SIZE || (tlv->length - AES_BLOCK_SIZE) > len) {
		wifi_dpp_dbg_print("%s:%d invalid wrapped_data length=%u\n", __func__, __LINE__, (unsigned int)tlv->length);
		return -1;
    }

    decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, tlv->value, 0);
	if (decrypted_len < 0) {
		return -1;
	}

    printf("%s:%d: Decrypted length:%d\n", __func__, __LINE__, decrypted_len);


    return tlv->length - AES_BLOCK_SIZE;
}

/* --- wifi_hal_dpp.c:2522-2569 --- */
INT
wifi_dppProcessConfigRequest(wifi_device_dpp_context_t *ctx)
{
    unsigned char buff[1024];
    int decrypted_len;
    wifi_tlv_t *tlv = NULL;
	wifi_dpp_session_data_t *data;
	wifi_dpp_instance_t *instance;
	unsigned char  *attrib;
	unsigned int len;

	data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

	attrib = ctx->received_frame.frame;
	len = ctx->received_frame.length;

    printf("%s:%d:Enter\n", __func__, __LINE__);
    
    if ((decrypted_len = get_config_frame_wrapped_data(attrib, len, instance, buff, 1024)) == -1) {
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    tlv = (wifi_tlv_t *)buff;

    tlv = get_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_enrollee_nonce, decrypted_len);
    if (tlv == NULL) {
		ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (tlv->length > sizeof(instance->enrollee_nonce)) {
        wifi_dpp_dbg_print("%s:%d enrollee nonce length mismatch %u/%u\n", __func__, __LINE__,
            (unsigned int)tlv->length, (unsigned int)instance->noncelen);
        ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    memcpy(instance->enrollee_nonce, tlv->value, tlv->length);
    printf("%s:%d: Enrollee nonce: E noncelen: %u I/R noncelen: %u\n", __func__, __LINE__, (unsigned int)tlv->length, (unsigned int)instance->noncelen);
    print_hex_dump(tlv->length, tlv->value);
   
	ctx->enrollee_status = RESPONDER_STATUS_OK; 

	return RETURN_OK;
}
}

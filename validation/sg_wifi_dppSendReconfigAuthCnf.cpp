/*
 * HANDLER: wifi_dppSendReconfigAuthCnf (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from fixes 1-2: start fix n / end fix n markers; the unfixed copy is the reproducer) from rdk-wifi-hal: src/wifi_hal_dpp.c:2931-3038 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-2.  It builds the DPP Reconfiguration Authentication
 * Confirm public action frame (header + wrapped data = AES-SIV (key instance->ke by digestlen, AAD = the 6-byte DPP frame body) of the transaction id, protocol version, initiator nonce, responder nonce and
 * reconfig flags), sends it with wifi_sendActionFrame(ap_index, sta_mac, frequency of the session channel, frame, len), re-reads the radio channel into session_data.channel, clears match_tran_id and
 * returns RETURN_OK; an unsupported digestlen -> enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE, RETURN_ERR.
 *
 * Scaffolding only: OpenSSL / AES-SIV are the real libraries; the callees set_tlv (wifi_tlv.c:49-58), print_hex_dump and channel_to_frequency (217-232) are verbatim support code; wifi_sendActionFrame is a
 * recording mock and wifi_getRadioChannel a stub (channel 6); wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppSendReconfigAuthCnf.
 */
#include "hwr_wsx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
hwr_wsx_cap_t hwr_wsx_cap;
#define wifi_dppSendReconfigAuthCnf hwr_sg_wifi_dppSendReconfigAuthCnf
/* support-code callees are renamed hwr_wsx_<name> so they do not clash with the copies of other harnesses */
#define set_tlv hwr_wsx_set_tlv
#define print_hex_dump hwr_wsx_print_hex_dump
#define channel_to_frequency hwr_wsx_channel_to_frequency
#define wifi_sendActionFrame hwr_wsx_sendActionFrame
#define wifi_getRadioChannel hwr_wsx_getRadioChannel

extern "C" {
/* wifi_sendActionFrame mock: records the call */
INT hwr_wsx_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency, UCHAR *frame, UINT len)
{
    hwr_wsx_cap.calls++;
    hwr_wsx_cap.ap = apIndex; memcpy(hwr_wsx_cap.sta, sta, 6); hwr_wsx_cap.freq = frequency; hwr_wsx_cap.len = len;
    memcpy(hwr_wsx_cap.frame, frame, len < sizeof(hwr_wsx_cap.frame) ? len : sizeof(hwr_wsx_cap.frame));
    return 0;
}
/* wifi_getRadioChannel stub: channel 6 */
INT hwr_wsx_getRadioChannel(INT radioIndex, ULONG *channel) { (void)radioIndex; *channel = 6; return 0; }

/* --- wifi_tlv.c:49-58 (verbatim, support code: set_tlv) --- */
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
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

/* --- wifi_hal_dpp.c:2931-3038 --- */
int
wifi_dppSendReconfigAuthCnf(wifi_device_dpp_context_t *dpp_ctx)
{
	siv_ctx ctx;
    unsigned char buff[2048];
    wifi_dppPublicActionFrame_t    *public_action_frame;
    ULONG ch_freq = 0;
    wifi_dpp_session_data_t    *data = NULL;
    wifi_tlv_t *tlv, *wrapped_tlv;
    unsigned int tlv_len, len, flags = 0;
    wifi_dpp_instance_t *instance;
    ULONG channel;

    /* ---------- start fix 1: a NULL context was dereferenced at once. */
    if (dpp_ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    wifi_dpp_dbg_print("%s:%d Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u\n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);

	data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    /* ---------- start fix 2: a NULL session instance was dereferenced (instance->noncelen / initiator_nonce / digestlen). */
    if (instance == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
    public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;
    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_recfg_auth_cnf;

    wifi_dpp_dbg_print("%s:%d Building TLVs\n", __func__, __LINE__);

    wrapped_tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;
    wrapped_tlv->type =  wifi_dpp_attrib_id_wrapped_data;

    tlv_len = 0;
    wifi_dpp_dbg_print("%s:%d tlv_len:%zu\n", __func__, __LINE__, tlv_len);

    tlv = (wifi_tlv_t *)&wrapped_tlv->value[AES_BLOCK_SIZE];

    wifi_dpp_dbg_print("%s:%d Building TLV transaction id %d\n", __func__, __LINE__,data->u.reconfig_data.match_tran_id);
  
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_transaction_id, sizeof(unsigned char), &data->u.reconfig_data.match_tran_id);
    tlv_len += (sizeof(unsigned char) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV protocol version\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(dpp_ctx->configurator_version), &dpp_ctx->configurator_version);
    tlv_len += (sizeof(dpp_ctx->configurator_version) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV initiator nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
    tlv_len += (instance->noncelen + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV responder nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_nonce, instance->noncelen, instance->responder_nonce);
    tlv_len += (instance->noncelen + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV reconfig flags\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_reconfig_flags, sizeof(unsigned int), (unsigned char*)&flags);
    tlv_len += (sizeof(unsigned int) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLVs done\n", __func__, __LINE__);

    wrapped_tlv->length = tlv_len + AES_BLOCK_SIZE; // wrapped tlv length = 58 + 16 = 74
    wifi_dpp_dbg_print("%s:%d wrapped_tlv->length:%zu\n", __func__, __LINE__, wrapped_tlv->length); 
    wifi_dpp_dbg_print("%s:%d digestlen:%d\n", __func__, __LINE__, instance->digestlen);

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            printf("Encryption Key reconfig_cnf: \n");
            print_hex_dump(instance->digestlen, instance->ke);
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
                    (unsigned char *)&public_action_frame->public_action_body, sizeof(wifi_dppPublicActionFrameBody_t));

    ch_freq = (unsigned long) channel_to_frequency(data->channel);
    wifi_dpp_dbg_print("%s:%d Trying sending frame on channel:%d\n", __func__, __LINE__, data->channel);

    len = sizeof(wifi_dppPublicActionFrame_t) + 4 +  wrapped_tlv->length;
    wifi_dpp_dbg_print("%s:%d Over the air len:%zu\n", __func__, __LINE__, len);
    wifi_sendActionFrame(dpp_ctx->ap_index, data->sta_mac, ch_freq, (unsigned char *)public_action_frame, len);

    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);
 // success, we should change the channel to current operating channel
    wifi_getRadioChannel(dpp_ctx->ap_index%2, &channel);
    data->channel = channel_to_frequency(channel);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);
    data->u.reconfig_data.match_tran_id=0;
    return RETURN_OK;
}
}

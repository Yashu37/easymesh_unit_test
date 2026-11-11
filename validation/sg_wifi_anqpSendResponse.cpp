/*
 * HANDLER: wifi_anqpSendResponse (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:404-664 (~/Desktop/G/rdk-wifi-hal), compiled with FEATURE_SUPPORT_PASSPOINT and RDK_ONEWIFI defined (the OneWifi build: no
 * interworking check, the frame goes out through wifi_hal_send_mgmt_frame).  This file holds the ORIGINAL code (no fixes).  It consumes the list of ANQP / HS2 elements (the function frees the nodes,
 * the elements and their data), serialises them into anqpBuffer[8192], builds a GAS initial response frame in buff[8192] (status success / protocol not supported / too large) and sends it.
 *
 * Scaffolding only: MAX_BUFF 8192 and MAC_STR_LEN 18 as in wifi_hal_anqp.c; the static gasCfg[GAS_CFG_TYPE_SUPPORTED] is declared like wifi_hal_anqp.c:61 and exposed by hwr_wsr_gas(); malloc / free are
 * counting wrappers (malloc failure injectable); wifi_hal_send_mgmt_frame and wifi_anqp_dbg_print are recording stubs; renamed hwr_sg_wifi_anqpSendResponse.
 */
#include "hwr_wsr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define FEATURE_SUPPORT_PASSPOINT 1
#define RDK_ONEWIFI 1
#define MAX_BUFF 8192
#define MAC_STR_LEN 18
hwr_wsr_world_t hwr_wsr_world;
static wifi_GASConfiguration_t gasCfg[GAS_CFG_TYPE_SUPPORTED];
extern "C" wifi_GASConfiguration_t *hwr_wsr_gas(void) { return gasCfg; }
extern "C" void *hwr_wsr_new(size_t n) { hwr_wsr_world.live++; return malloc(n); }
static void *hwr_wsr_malloc(size_t n)
{
	hwr_wsr_world_t *w = &hwr_wsr_world;
	if (w->in_func) { w->fn_mallocs++; if (w->fail_at && w->fn_mallocs == w->fail_at) return NULL; }
	w->live++;
	return malloc(n);
}
static void hwr_wsr_free(void *p) { if (p) hwr_wsr_world.live--; free(p); }
static int wifi_hal_send_mgmt_frame(int apIndex, mac_address_t sta, const unsigned char *data, size_t data_len, unsigned int freq, unsigned int wait)
{
	hwr_wsr_world_t *w = &hwr_wsr_world;
	w->mgmt_calls++; w->ap = apIndex; w->sta_ptr = (const unsigned char *)sta; if (sta) memcpy(w->sta_copy, sta, 6);
	w->len = data_len; w->freq = freq; w->wait = wait;
	memcpy(w->frame, data, data_len < HWR_WSR_FRAMEMAX ? data_len : HWR_WSR_FRAMEMAX);
	return 0;
}
static void hwr_wsr_dbg(int level, const char *format, ...) { hwr_wsr_world.dbg_calls++; }
#define malloc hwr_wsr_malloc
#define free hwr_wsr_free
#define wifi_anqp_dbg_print hwr_wsr_dbg
#define wifi_anqpSendResponse hwr_sg_wifi_anqpSendResponse

extern "C" {
/* --- wifi_hal_anqp.c:404-664 --- */
INT wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *head)
{
    char macStr[MAC_STR_LEN];
    memset(macStr,0,sizeof(macStr));
    if(sta){
        snprintf(macStr, MAC_STR_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
             wifi_anqp_dbg_print(1, "%s:%d: converted mac: %s ap_index=%d\n", __func__, __LINE__,macStr,apIndex);
    }

    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpSendResponse start on AP: %d \n", __func__,__LINE__,apIndex+1);
    wifi_anqp_dbg_print(1, "STA: %s\n",macStr);
    if (head == NULL)
    {
        wifi_anqp_dbg_print(1, "%s:%d: node list is null returning -1:    \n", __func__,__LINE__);
        return RETURN_ERR;
    }

    unsigned char wfa_oui[3] = {0x50, 0x6f, 0x9a};

    unsigned char buff[MAX_BUFF];
    unsigned char anqpBuffer[MAX_BUFF];
    unsigned char *next_pos;
    next_pos = &anqpBuffer[0];

    int total_length = 0;

    wifi_anqp_node_t *tmp = NULL;

    wifi_anqp_elem_t *elem = NULL;
    wifi_anqp_element_format_t *anqp_info = NULL;
    wifi_hs_2_anqp_element_format_t *anqp_hs_2_info = NULL;

    while (head != NULL)
    {
        elem = head->value;
        if (NULL == elem)
        {
            head = head->next;
            continue;
        }
        //construct the buffer for gas
        if (elem->type == wifi_anqp_id_type_anqp)
        {
            if (elem->data && elem->len)
            {
                total_length += sizeof(wifi_anqp_element_format_t) + elem->len;
                //8179 +13(max gas frame size = 8192)
                if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
                {
                    wifi_anqp_dbg_print(1, "%s:%d: Anqp_info length buffer is too big to process returning: %d\n", __func__, __LINE__, total_length);
                    break;
                }

                anqp_info = (wifi_anqp_element_format_t *)malloc(sizeof(wifi_anqp_element_format_t) + elem->len);
                if (anqp_info == NULL) {
                    wifi_anqp_dbg_print(1, "%s:%d: malloc failed\n", __func__, __LINE__);
                    break;
                }
                memset((unsigned char *)anqp_info, 0, sizeof(wifi_anqp_element_format_t) + elem->len);

                wifi_anqp_dbg_print(1, "%s:%d: Anqp Element type received:    \n", __func__, __LINE__);
                anqp_info->info_id = elem->u.anqp_elem_id;
                anqp_info->len = elem->len;

                wifi_anqp_dbg_print(1, "%s:%d: Anqp_info length:    %d:\n", __func__, __LINE__, anqp_info->len);

                memcpy(anqp_info->info, elem->data, elem->len);

                memcpy(next_pos, anqp_info, sizeof(wifi_anqp_element_format_t) + anqp_info->len);
                next_pos += sizeof(wifi_anqp_element_format_t) + anqp_info->len;
                if (anqp_info)
                {
                    wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info:    \n", __func__, __LINE__);
                    free(anqp_info);
                }
            }
        }
        else if (elem->type == wifi_anqp_id_type_hs)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Anqp Element type HS2  received \n", __func__, __LINE__);
            if (elem->data && elem->len)
            {
                total_length += sizeof(wifi_hs_2_anqp_element_format_t) + elem->len;
                wifi_anqp_dbg_print(1, "%s:%d: anqp_hs_2_info elem length: %hu\n", __func__, __LINE__, elem->len);
                //8179 +13(gas frame header = 8192)
                if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
                {
                    wifi_anqp_dbg_print(1, "%s:%d: Anqp buffer is too big to process returning: %d\n", __func__, __LINE__, total_length);
                    break;
                }
                anqp_hs_2_info = (wifi_hs_2_anqp_element_format_t *)malloc(sizeof(wifi_hs_2_anqp_element_format_t) + elem->len);
                if (anqp_hs_2_info == NULL) {
                    wifi_anqp_dbg_print(1, "%s:%d: malloc failed\n", __func__, __LINE__);
                    break;
                }
                memset((unsigned char *)anqp_hs_2_info, 0, sizeof(wifi_hs_2_anqp_element_format_t) + elem->len);
                anqp_hs_2_info->info_id = wifi_anqp_element_name_vendor_specific;
                anqp_hs_2_info->len = elem->len + 6;
                wifi_anqp_dbg_print(1, "%s:%d: anqp_hs_2_info length: %hu\n", __func__, __LINE__, anqp_hs_2_info->len);
                anqp_hs_2_info->type = 0x11;
                anqp_hs_2_info->subtype = elem->u.anqp_hs_id;
                anqp_hs_2_info->reserved = 0x00;
                memcpy(anqp_hs_2_info->oi, wfa_oui, sizeof(wfa_oui));

                memcpy(anqp_hs_2_info->payload, elem->data, elem->len);

                // char buffer[elem->len - 6];
                // memcpy(buffer, anqp_hs_2_info->payload, elem->len - 6);
                // wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info start: %d\n", __func__, __LINE__);
                // for (int i = 0; i < elem->len - 6; i++)
                // {
                //     wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info length: 0x%02x\n", __func__, __LINE__, buffer[i]);
                //     printf("0x%02x      ", buffer[i]);
                // }
                // wifi_anqp_dbg_print("%s:%d:\n", __func__, __LINE__);
                // wifi_anqp_dbg_print("%s:%d: HS2 End\n", __func__, __LINE__);

                // char buffer1[total_length];
                // memcpy(buffer1, anqp_hs_2_info, total_length);

                // wifi_anqp_dbg_print("%s:%d: HS2 Buffer Start: %d\n", __func__, __LINE__);
                // for (int i = 0; i < total_length; i++)
                // {
                //     wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info length: 0x%02x\n", __func__, __LINE__, buffer1[i]);
                // }
                // wifi_anqp_dbg_print("%s:%d:\n", __func__, __LINE__);
                // wifi_anqp_dbg_print("%s:%d: HS2 Buffer End\n", __func__, __LINE__);

                memcpy(next_pos, anqp_hs_2_info, sizeof(wifi_hs_2_anqp_element_format_t) + elem->len /*anqp_hs_2_info->len-6*/);
                next_pos += sizeof(wifi_hs_2_anqp_element_format_t) + elem->len /*anqp_hs_2_info->len-6*/;

                if (anqp_hs_2_info)
                {
                    wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_hs_2_info elem-data:    \n", __func__, __LINE__);
                    free(anqp_hs_2_info);
                }
            }
        }
        if (elem->data)
        {
            wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info elem-data:    \n", __func__, __LINE__);
            free(elem->data);
            elem->data = NULL;
        }
        free(elem);
        tmp = head;
        head = head->next;
        free(tmp);
        tmp = NULL;
    }

    //Free up memory in case of too large response
    while (head)
    {
        elem = head->value;

        if (elem)
        {
            if (elem->data)
            {
                wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info elem-data:    \n", __func__, __LINE__);
                free(elem->data);
                elem->data = NULL;
            }
            free(elem);
        }
        tmp = head;
        head = head->next;
        free(tmp);
        tmp = NULL;
    }
 
#if defined (FEATURE_SUPPORT_PASSPOINT)
#if !defined (RDK_ONEWIFI)
    BOOL enabled;
    INT rc;
    rc = wifi_getApInterworkingServiceEnable(apIndex, &enabled);
    if (rc == RETURN_OK)
    {
        if (!enabled)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking is disabled on AP: %d. Not sending any GAS Responses \n", __func__, __LINE__,(apIndex+1));
            return RETURN_ERR;
        }
    }
    else
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking enabled flag could not be retreived for AP: %d. Not sending any GAS Responses \n", __func__, __LINE__,(apIndex+1));
        return RETURN_ERR;
    }
#endif
#else
    wifi_anqp_dbg_print(1, "%s:%d: Error: FEATURE NOT SUPPORTED", __func__, __LINE__);
    return RETURN_ERR;
#endif

    wifi_anqp_dbg_print(1, "%s:%d: Interworking is enabled will proceed to gas response send on AP: %d \n", __func__,__LINE__,apIndex+1);
    wifi_anqp_dbg_print(1, "STA: %s. \n", macStr);

    //8179 +13(gas frame header = 8192)
    if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
    {
        wifi_anqp_dbg_print(1, "%s:%d: Anqp buffer is too big to process.%d\n", __func__, __LINE__, total_length);
        return RETURN_ERR;
    }

    /*For gas frame and concatenating anqp buffer contructed above */
    wifi_anqpResponseFrame_t *anqp_gas_initial_response_frame = NULL;

    anqp_gas_initial_response_frame = (wifi_anqpResponseFrame_t *)buff;

    anqp_gas_initial_response_frame->public_action_hdr.cat = 0x04;
    anqp_gas_initial_response_frame->public_action_hdr.action = 0x0b;
    anqp_gas_initial_response_frame->gas_resp_body.token = token;
    anqp_gas_initial_response_frame->gas_resp_body.comeback_delay = 0; //we are not supporting fragmentation or we dont have a server
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.id = 0x6c;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.len = 0x02;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.proto_tuple.query_rsp_info = (unsigned char)gasCfg[GAS_CFG_TYPE_SUPPORTED - 1].QueryResponseLengthLimit;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.proto_tuple.adv_proto_id = gasCfg[GAS_CFG_TYPE_SUPPORTED - 1].AdvertisementID; //currently only anqp supported.


    if (total_length == 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: total Length is 0 from the list will send frame protocol not supported.\n", __func__, __LINE__);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_advertisement_protocol_not_supported;
    }
    else if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
    {
        wifi_anqp_dbg_print(1, "%s:%d: Anqp buffer is too big to process: %d, we are setting gas response length to zero.\n", __func__, __LINE__, total_length);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_query_response_too_large;
        total_length = 0; //as per spec we need to set response length to zero
    }
    else
    {
        wifi_anqp_dbg_print(1, "%s:%d: we have a gas query response to fill the buffer\n", __func__, __LINE__);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_status_success;
    }

    anqp_gas_initial_response_frame->rsp_len = total_length;
    memcpy(anqp_gas_initial_response_frame->rsp_body, anqpBuffer, total_length);

    wifi_anqp_dbg_print(1, "%s:%d: we have a gas query response to fill the buffer\n", __func__, __LINE__);
#if !defined (RDK_ONEWIFI) || defined(TCHCBRV2_PORT)
    ULONG hm_channel = 0;
    UINT radioIndex = apIndex % 2;
    wifi_getRadioChannel(radioIndex, &hm_channel);
    wifi_anqp_dbg_print(1, "%s:%d: gathered channel for sending the frame out: %lu\n", __func__, __LINE__, hm_channel);
    unsigned int freq = 0;
    freq = channel_to_frequency(hm_channel);

    wifi_anqp_dbg_print(1, "%s:%d: frequency for sending the frame out: %lu\n", __func__, __LINE__, freq);
    wifi_anqp_dbg_print(1, "%s:%d: apIndex for sending the frame out: %d\n", __func__, __LINE__, apIndex + 1);

    wifi_sendActionFrame(apIndex, sta, freq, (unsigned char *)anqp_gas_initial_response_frame, sizeof(wifi_anqpResponseFrame_t) + total_length);
#else
    wifi_hal_send_mgmt_frame(apIndex,  sta,(unsigned char *)anqp_gas_initial_response_frame,(sizeof(wifi_anqpResponseFrame_t) + total_length),0, 0);
#endif
    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpSendResponse exit\n", __func__, __LINE__);
    return RETURN_OK;
}
}

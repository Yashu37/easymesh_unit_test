/*
 * HANDLER: wifi_dppProcessReconfigAnnouncement (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:2365-2389 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It checks a received DPP Reconfiguration Announcement
 * frame: finds the C-sign key hash attribute in the attributes after the 6-byte action frame body, dumps it next to the caller's key hash and returns RETURN_OK only when the attribute is exactly
 * SHA256_DIGEST_LENGTH bytes long and equal to the first 32 bytes of key_hash (OneWifi passes g_easy_connect.csign[apIndex].sign_key_hash, a 512-byte field).
 *
 * Scaffolding only: the callees get_tlv (wifi_tlv.c, with the shared bounds fix 3 = finding #205 of wifi_dppProcessReconfigAuthResponse, not recounted here) and print_hex_dump (verbatim) are
 * support code; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes to a no-op sink; renamed hwr_sg_wifi_dppProcessReconfigAnnouncement.
 */
#include "hwr_wrn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppProcessReconfigAnnouncement hwr_sg_wifi_dppProcessReconfigAnnouncement
/* support-code callees are renamed hwr_wrn_<name> so they do not clash with the copies of other harnesses */
#define get_tlv hwr_wrn_get_tlv
#define print_hex_dump hwr_wrn_print_hex_dump

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

/* --- wifi_hal_dpp.c:2365-2389 --- */
INT
wifi_dppProcessReconfigAnnouncement(unsigned char *frame, unsigned int len, unsigned char *key_hash)
{
	wifi_tlv_t *tlv;
	wifi_dppPublicActionFrameBody_t *action;

	action = (wifi_dppPublicActionFrameBody_t *)frame;

	tlv = (wifi_tlv_t *)action->attrib;
        tlv = get_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_C_sign_key_hash, len);
	if (tlv == NULL) {
		return RETURN_ERR;

	}

	printf("%s:%d Matching C-sign\n", __func__, __LINE__);
	print_hex_dump(tlv->length, tlv->value);
	print_hex_dump(tlv->length, key_hash);

	if ((tlv->length != SHA256_DIGEST_LENGTH) || (memcmp(tlv->value, key_hash, SHA256_DIGEST_LENGTH) != 0)) {
		return RETURN_ERR;
	}

	return RETURN_OK;
}
}

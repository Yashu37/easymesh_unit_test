/*
 * HANDLER: wifi_dppChirp (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:3645-3709 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-2 (start fix n / end fix n markers; the unfixed copy is the reproducer).  It builds the 8-byte test signature plus four TLVs (chirp
 * command, vap name "ath<apIndex>" as 16 bytes, station mac, 44 bytes of canned chirp frame) with set_tlv, sends the datagram to 127.0.0.1:8888, closes the socket and
 * returns RETURN_OK (RETURN_ERR, after closing, when sendto fails).
 *
 * Scaffolding only: socket / sendto / close are recording stubs (macros below); set_tlv is the real wifi_tlv.c:49-58 copied verbatim; printf goes to a no-op sink; the signature array is the one of wifi_hal_anqp.c:50;
 * renamed hwr_sg_wifi_dppChirp.
 */
#include "hwr_wch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#define RETURN_OK 0
#define RETURN_ERR -1
hwr_wch_world_t hwr_wch_world;
static unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};
extern "C" const unsigned char *hwr_wch_sig(void) { return wifi_common_hal_test_signature; }

/* --- wifi_tlv.c:49-58 (verbatim, support code) --- */
#define set_tlv hwr_wch_set_tlv
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}

static int hwr_wch_socket(int domain, int type, int protocol)
{
	hwr_wch_world_t *w = &hwr_wch_world;
	w->socket_calls++; w->sock_domain = domain; w->sock_type = type; w->sock_proto = protocol;
	if (w->socket_fail) { errno = EMFILE; return -1; }
	return 5;
}
static ssize_t hwr_wch_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *a, socklen_t alen)
{
	hwr_wch_world_t *w = &hwr_wch_world;
	const struct sockaddr_in *in = (const struct sockaddr_in *)a;
	w->sendto_calls++; w->sent_len = len; memcpy(w->sent, buf, len < sizeof(w->sent) ? len : sizeof(w->sent));
	w->sent_addr_family = in->sin_family; w->sent_port = ntohs(in->sin_port); w->sent_ip = ntohl(in->sin_addr.s_addr);
	if (w->send_fail) { errno = ECONNREFUSED; return -1; }
	return len;
}
static int hwr_wch_close(int fd) { hwr_wch_world.closes++; return 0; }
static void hwr_wch_dbg(const char *format, ...) { }
#define socket hwr_wch_socket
#define sendto hwr_wch_sendto
#define close hwr_wch_close
#define printf hwr_wch_dbg
#define wifi_dppChirp hwr_sg_wifi_dppChirp

extern "C" {
/* --- wifi_hal_dpp.c:3645-3709 --- */
int wifi_dppChirp(unsigned int apIndex, mac_address_t sta)
{
	int ret, sockfd;
	struct sockaddr_in sockaddr;
    unsigned char msg[1024];
    char interface_name[32];
	unsigned int len, tlv_len = 0;
    wifi_tlv_t *tlv;
	unsigned short port = 8888;

    unsigned char test_data[] = {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x0e, 0x1e, 0x10, 0x20, 0x00, 0xa8, 0x21, 0x0b, 0x0f,
		0xb0, 0xc8, 0x98, 0x96, 0x4a, 0xa0, 0xa6, 0xdf, 0xfa, 0x62, 0x62, 0x7f, 0xbd, 0x6d, 0xaa, 0x60,
		0xf8, 0x04, 0x82, 0xf8, 0xd6, 0x36, 0x98, 0x97, 0x61, 0xa2, 0x27, 0x0a
    };

    wifi_test_command_id_t cmd = wifi_test_command_id_chirp;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    /* ---------- start fix 1: sta was passed to set_tlv (memcpy of 6 bytes) without a NULL check. */
    if (sta == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */
   
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        printf("%s:%d: Error opening raw socket, err:%d\n", __func__, __LINE__, errno);
        return RETURN_ERR;
    }

    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family   = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_aton("127.0.0.1" , &sockaddr.sin_addr);

    memcpy(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature));
    len = sizeof(wifi_common_hal_test_signature);


    tlv = (wifi_tlv_t *)&msg[sizeof(wifi_common_hal_test_signature)];

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_cmd, sizeof(wifi_test_command_id_t), (unsigned char*)&cmd);
    tlv_len += (4 + sizeof(wifi_test_command_id_t));

    /* ---------- start fix 2: apIndex is unsigned; %d printed a negative name for values >= 0x80000000. */
    sprintf(interface_name, "ath%u", apIndex);
    /* ---------- end fix 2 */
    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, interface_name);
    tlv_len += (4 + IFNAMSIZ);


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), sta);
    tlv_len += (4 + sizeof(mac_address_t));


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, sizeof(test_data), test_data);
    tlv_len += (4 + sizeof(test_data));

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
        printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

	return RETURN_OK;
}
}

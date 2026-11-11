/*
 * HANDLER: wifi_anqpStartTest (src/wifi_hal_anqp.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal_anqp.c:820-889 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer; the apIndex %d wrong-behaviour failures are not fixed).  It opens a UDP socket (RETURN_ERR when that fails),
 * builds the 8-byte test signature plus four TLVs (ANQP command, vap name "ath<apIndex>" as 16 bytes, station mac, 42 bytes of canned ANQP query data) with set_tlv, sends the 92 bytes to
 * 127.0.0.1:8889, closes the socket and returns RETURN_OK (RETURN_ERR, after closing, when sendto fails).
 *
 * Scaffolding only: socket / sendto / close are recording stubs (macros below); set_tlv is the real wifi_tlv.c:49-58 copied verbatim; wifi_anqp_dbg_print is a no-op; the signature array is the
 * PLATFORM_LINUX one of wifi_hal_anqp.c:48; renamed hwr_sg_wifi_anqpStartTest.
 */
#include "hwr_wst.h"
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

hwr_wst_world_t hwr_wst_world;
static unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};
extern "C" const unsigned char *hwr_wst_sig(void) { return wifi_common_hal_test_signature; }

/* --- wifi_tlv.c:49-58 (verbatim, support code) --- */
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}

static int hwr_wst_socket(int domain, int type, int protocol)
{
	hwr_wst_world_t *w = &hwr_wst_world;
	w->socket_calls++; w->sock_domain = domain; w->sock_type = type; w->sock_proto = protocol;
	if (w->socket_fail) { errno = EMFILE; return -1; }
	return 5;
}
static ssize_t hwr_wst_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *a, socklen_t alen)
{
	hwr_wst_world_t *w = &hwr_wst_world;
	const struct sockaddr_in *in = (const struct sockaddr_in *)a;
	w->sendto_calls++; w->sent_len = len; memcpy(w->sent, buf, len < sizeof(w->sent) ? len : sizeof(w->sent));
	w->sent_addr_family = in->sin_family; w->sent_port = ntohs(in->sin_port); w->sent_ip = ntohl(in->sin_addr.s_addr);
	if (w->send_fail) { errno = ECONNREFUSED; return -1; }
	return len;
}
static int hwr_wst_close(int fd) { hwr_wst_world.closes++; return 0; }
static void hwr_wst_dbg(int level, const char *format, ...) { }
#define socket hwr_wst_socket
#define sendto hwr_wst_sendto
#define close hwr_wst_close
#define wifi_anqp_dbg_print hwr_wst_dbg
#define wifi_anqpStartTest hwr_sg_wifi_anqpStartTest

extern "C" {
/* --- wifi_hal_anqp.c:820-889 --- */
int wifi_anqpStartTest(unsigned int apIndex, mac_address_t sta)
{
    int ret, sockfd;
    struct sockaddr_in sockaddr;
    unsigned char msg[1024];
    char interface_name[32];
    size_t len = 0, tlv_len = 0;
    wifi_tlv_t *tlv;
    unsigned short port = 8889;
    //All ANQP HS2 Query Types defined in RDKB-16611 and RDKB-1317
    unsigned char test_data[42] = {
        0x04, 0x0a, 0x1a, 0x6c, 0x02, 0x00, 0x00, 0x22, 0x00, 0x00, 0x01, 0x0e, 0x00, 0x01, 0x01, 0x0c, 0x01,
        0x07, 0x01, 0x08, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0xdd, 0xdd, 0x0b, 0x00, 0x50, 0x6f, 0x9a,
        0x11, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
    //Based on Sniffer Data
    /*unsigned char test_data[32] = {
        0x04, 0x0a, 0x1a, 0x6c, 0x02, 0x00, 0x00, 0x17, 0x00, 0x00, 0x01, 0x04, 0x00, 0x0c, 0x01, 0x07,
        0x01, 0xdd, 0xdd, 0x07, 0x00, 0x50, 0x6f, 0x9a, 0x11, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};*/

    wifi_test_command_id_t cmd = wifi_test_command_id_anqp;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    /* ---------- start fix 1: sta was passed to set_tlv (memcpy of 6 bytes) without a NULL check. */
    if (sta == NULL)
    {
        wifi_anqp_dbg_print(1, "%s:%d: NULL sta\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error opening raw socket, err:%d\n", __func__, __LINE__, errno);
        return RETURN_ERR;
    }

    //setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_aton("127.0.0.1", &sockaddr.sin_addr);

    memcpy(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature));
    len = sizeof(wifi_common_hal_test_signature);

    tlv = (wifi_tlv_t *)&msg[sizeof(wifi_common_hal_test_signature)];

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_cmd, sizeof(wifi_test_command_id_t), (unsigned char*)&cmd);
    tlv_len += (4 + sizeof(wifi_test_command_id_t));

    sprintf(interface_name, "ath%d", apIndex);
    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, interface_name);
    tlv_len += (4 + IFNAMSIZ);

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), sta);
    tlv_len += (4 + sizeof(mac_address_t));

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, sizeof(test_data), test_data);
    tlv_len += (4 + sizeof(test_data));

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

    return RETURN_OK;
}
}

/*
 * HANDLER: wifi_send_test_frame (src/wifi_hal_frame_test.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_frame_test.c:59-116 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-4 (start fix n / end fix n markers; the unfixed copy is the reproducer).  It builds the 8-byte test signature plus five TLVs
 * (command, vap name from arg->interface_name as 16 bytes, station mac from arg->mac, direction, the raw frame) in a local msg[2048] with set_tlv, sends the datagram to 127.0.0.1:8888, closes the socket
 * and returns RETURN_OK (RETURN_ERR, after closing, when sendto fails; RETURN_ERR when the socket cannot be created).
 *
 * Scaffolding only: socket / sendto / close are recording stubs (macros below); set_tlv is the real wifi_tlv.c:49-58 copied verbatim; printf goes to a no-op sink; the signature array is the one of
 * wifi_hal_frame_test.c:42; renamed hwr_sg_wifi_send_test_frame.
 */
#include "hwr_wft.h"
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
hwr_wft_world_t hwr_wft_world;
static unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};
extern "C" const unsigned char *hwr_wft_sig(void) { return wifi_common_hal_test_signature; }

/* --- wifi_tlv.c:49-58 (verbatim, support code) --- */
#define set_tlv hwr_wft_set_tlv
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}

static int hwr_wft_socket(int domain, int type, int protocol)
{
	hwr_wft_world_t *w = &hwr_wft_world;
	w->socket_calls++; w->sock_domain = domain; w->sock_type = type;
	if (w->socket_fail) { errno = EMFILE; return -1; }
	return 5;
}
static ssize_t hwr_wft_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *a, socklen_t alen)
{
	hwr_wft_world_t *w = &hwr_wft_world;
	const struct sockaddr_in *in = (const struct sockaddr_in *)a;
	w->sendto_calls++; w->sent_len = len; memcpy(w->sent, buf, len < sizeof(w->sent) ? len : sizeof(w->sent));
	w->sent_addr_family = in->sin_family; w->sent_port = ntohs(in->sin_port); w->sent_ip = ntohl(in->sin_addr.s_addr);
	if (w->send_fail) { errno = ECONNREFUSED; return -1; }
	return len;
}
static int hwr_wft_close(int fd) { hwr_wft_world.closes++; return 0; }
static void hwr_wft_dbg(const char *format, ...) { }
#define socket hwr_wft_socket
#define sendto hwr_wft_sendto
#define close hwr_wft_close
#define printf hwr_wft_dbg
#define wifi_send_test_frame hwr_sg_wifi_send_test_frame

extern "C" {
/* --- wifi_hal_frame_test.c:59-116 --- */
int wifi_send_test_frame(unsigned char *frame, size_t frame_len, frame_test_arg_t *arg, wifi_test_command_id_t cmd, wifi_direction_t dir)
{
   int ret, sockfd;
   struct sockaddr_in sockaddr;
   unsigned char msg[2048];
   unsigned int len, tlv_len = 0;
   wifi_tlv_t *tlv;
   unsigned short port = 8888;

   //printf("%s:%d: Enter: data length:%d\n", __func__, __LINE__, frame_len);

    /* ---------- start fix 1: arg was dereferenced (interface_name, mac) without a NULL check. */
   if (arg == NULL) {
       return RETURN_ERR;
   }
   /* ---------- end fix 1 */

   /* ---------- start fix 2: frame was copied by set_tlv (memcpy of frame_len bytes) without a NULL check. */
   if (frame == NULL && frame_len > 0) {
       return RETURN_ERR;
   }
   /* ---------- end fix 2 */

   /* ---------- start fix 3: frame_len was never checked against the room left in msg[2048] (stack overflow; also wraps in set_tlv's unsigned short length). */
   if (frame_len > sizeof(msg) - sizeof(wifi_common_hal_test_signature) - (4 + sizeof(wifi_test_command_id_t)) - (4 + IFNAMSIZ) - (4 + sizeof(mac_address_t)) - (4 + 1) - 4) {
       return RETURN_ERR;
   }
   /* ---------- end fix 3 */

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

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, (unsigned char*)arg->interface_name);
    tlv_len += (4 + IFNAMSIZ);


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), arg->mac);
    tlv_len += (4 + sizeof(mac_address_t));

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_direction, 1, (unsigned char*)&dir);
    /* ---------- start fix 4: the direction TLV is 4 header bytes + 1 value byte; it was counted as 1 + sizeof(mac_address_t) = 7, sending 2 bytes past the data. */
    tlv_len += (4 + 1);
    /* ---------- end fix 4 */


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, frame_len, frame);
    tlv_len += (4 + frame_len);

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
       printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
       close(sockfd);
       return RETURN_ERR;
    }

    close(sockfd);

    //printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

    return RETURN_OK;
}
}

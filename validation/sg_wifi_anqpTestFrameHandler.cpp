/*
 * HANDLER: wifi_anqpTestFrameHandler (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:692-811 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It is the ANQP test-frame receive thread: it binds a UDP
 * socket to 127.0.0.1:8889, and for every datagram that starts with the 8-byte test signature it looks up TLVs (command, vap name, station mac, raw frame) with get_tlv and, for the ANQP command, copies them into
 * the local cmd / interface_name[32] / bmac[6] / frame[128] with the TLV's own length and hands the frame to mgmt_frame_received_callback; it ends when select fails and returns its argument.
 *
 * Scaffolding only: socket / bind / select / recvfrom / close / prctl are scripted stubs (macros below); get_tlv is the real wifi_tlv.c:29-46 copied verbatim; mgmt_frame_received_callback and
 * wifi_anqp_dbg_print are stubs; the signature array is the PLATFORM_LINUX one of wifi_hal_anqp.c:48; renamed hwr_sg_wifi_anqpTestFrameHandler.
 */
#include "hwr_wtf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

hwr_wtf_world_t hwr_wtf_world;
unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};

/* --- wifi_tlv.c:29-46 (verbatim, support code) --- */
wifi_tlv_t *get_tlv(unsigned char *buff, unsigned short attrib, unsigned short len)
{
    unsigned int total_len = 0;
    bool found = false;
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    while (total_len < len) {
        if (tlv->type == attrib) {
            found = true;
            break;
        }

        total_len += (2*sizeof(unsigned short) + tlv->length);
        tlv = (wifi_tlv_t *)((unsigned char *)tlv + 2*sizeof(unsigned short) + tlv->length);
    }

    return (found == true) ? tlv:NULL;
}

static int hwr_wtf_socket(int domain, int type, int protocol) { if (hwr_wtf_world.socket_fail) { errno = EACCES; return -1; } return 3; }
static int hwr_wtf_bind(int fd, const struct sockaddr *a, socklen_t l) { hwr_wtf_world.binds++; if (hwr_wtf_world.bind_fail) { errno = EADDRINUSE; return -1; } return 0; }
static int hwr_wtf_close(int fd) { hwr_wtf_world.closes++; return 0; }
static int hwr_wtf_prctl(int option, ...) { hwr_wtf_world.prctl_calls++; return 0; }
static int hwr_wtf_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
	hwr_wtf_world_t *x = &hwr_wtf_world;
	if (x->sel0 && !x->sel0_done) { x->sel0_done = 1; return 0; }
	if (x->recvfail && !x->recv_done) return 1;
	return x->next < x->ndg ? 1 : -1;
}
static ssize_t hwr_wtf_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *a, socklen_t *l)
{
	hwr_wtf_world_t *x = &hwr_wtf_world;
	if (x->recvfail && !x->recv_done) { x->recv_done = 1; return -1; }
	unsigned n = x->dglen[x->next] < len ? x->dglen[x->next] : (unsigned)len;
	memcpy(buf, x->dgbuf[x->next], n); x->next++;
	return n;
}
static int mgmt_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir)
{
	hwr_wtf_world_t *x = &hwr_wtf_world;
	int i = x->cb_calls++;
	if (i < HWR_WTF_MAXCB) { x->cb_ap[i] = ap_index; memcpy(x->cb_mac[i], sta_mac, 6); memcpy(x->cb_frame[i], frame, 128); x->cb_len[i] = len; x->cb_type[i] = type; x->cb_dir[i] = dir; }
	return 0;
}
static void hwr_wtf_dbg(int level, const char *format, ...) { }
#define socket hwr_wtf_socket
#define bind hwr_wtf_bind
#define close hwr_wtf_close
#define prctl hwr_wtf_prctl
#define select hwr_wtf_select
#define recvfrom hwr_wtf_recvfrom
#define wifi_anqp_dbg_print hwr_wtf_dbg
#define wifi_anqpTestFrameHandler hwr_sg_wifi_anqpTestFrameHandler
#define PR_SET_NAME 15

extern "C" {
/* --- wifi_hal_anqp.c:692-811 --- */
void *wifi_anqpTestFrameHandler(void *arg)
{
    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpTestFrameHandler entry:    \n", __func__, __LINE__);
    int sockfd;
    int ret = RETURN_OK;
    char interface_name[32];
    unsigned char msg[1024];
    size_t len = 0;
    wifi_test_command_id_t cmd;
    mac_address_t bmac;
    unsigned char frame[128];
    wifi_tlv_t *tlv;
    fd_set rfds;
    struct timeval tv;
    int retval, ap_index;
    bool exit = false;

    struct sockaddr_in saddr;
    socklen_t slen;
    unsigned short port = 8889;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error opening raw socket , err:%d\n", __func__, __LINE__, errno);
        return NULL;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_aton("127.0.0.1", &saddr.sin_addr);

    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error binding to interface, err:%d\\n", __func__, __LINE__, errno);
        close(sockfd);
        return NULL;
    }

    while (exit == false)
    {

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == 0)
        {
            continue;
        }
        else if (retval == -1)
        {
            exit = true;
            continue;
        }

        if (FD_ISSET(sockfd, &rfds) == 0)
        {
            continue;
        }
        if ((ret = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&saddr, &slen)) < 0)
        {
            continue;
        }

        if (memcmp(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature)) != 0)
        {
            continue;
        }

        wifi_anqp_dbg_print(1, "%s:%d: Received test signature\n", __func__, __LINE__);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_cmd, ret)) == NULL)
        {
            continue;
        }
        memcpy((unsigned char *)&cmd, tlv->value, tlv->length);

        switch (cmd)
        {
        case wifi_test_command_id_anqp:
            wifi_anqp_dbg_print(1, "%s:%d: Received anqp test command\n", __func__, __LINE__);
            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_vap_name, ret)) == NULL)
            {
                continue;
            }
            memcpy(interface_name, tlv->value, tlv->length);
            sscanf(interface_name, "ath%d", &ap_index);

            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_sta_mac, ret)) == NULL)
            {
                continue;
            }
            memcpy(bmac, tlv->value, tlv->length);

            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_raw, ret)) == NULL)
            {
                continue;
            }
            memcpy(frame, tlv->value, tlv->length);
            wifi_anqp_dbg_print(1, "%s:%d: Calling mgmt frame receive\n", __func__, __LINE__);

            mgmt_frame_received_callback(ap_index, bmac, frame, len, WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
            break;

        default:
            break;
        }
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);
    return arg;
}
}

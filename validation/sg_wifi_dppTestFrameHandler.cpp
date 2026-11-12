/*
 * HANDLER: wifi_dppTestFrameHandler (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:3431-3532 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-7 (start fix n / end fix n markers; the unfixed copy is the reproducer).  It is the thread routine of the DPP test frame receiver: when the
 * file /nvram/wifiDppTest is readable it opens the test socket (create_test_socket) and loops forever: for every datagram that starts with the 8-byte test signature it looks up TLVs (command, vap name, station
 * mac, raw frame) with get_tlv and, for the chirp / reconfig auth response commands, copies them into the local cmd / interface_name[32] / bmac[6] / frame[1024] with the TLV's own length, parses the ap index out of
 * "ath<N>" and hands the frame to mgmt_frame_received_callback.
 *
 * Scaffolding only: access / create_test_socket / select / recvfrom / close / prctl are scripted stubs (macros below; select throws once the scripted datagrams are consumed, because the function has no other exit
 * and ends its loop only on a select failure in no case); get_tlv is the real wifi_tlv.c:29-46 copied verbatim; mgmt_frame_received_callback and wifi_dpp_dbg_print are stubs; the signature array is the one of
 * wifi_hal_anqp.c:50; the static function is exported through hwr_sg_wifi_dppTestFrameHandler.
 */
#include "hwr_wtd.h"
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

/* names renamed so they do not clash with the copies in the other test-frame harnesses */
#define wifi_common_hal_test_signature hwr_wtd_sig
#define get_tlv hwr_wtd_get_tlv
#define mgmt_frame_received_callback hwr_wtd_mgmt_frame_received_callback
#define RETURN_OK 0
#define RETURN_ERR -1
hwr_wtd_world_t hwr_wtd_world;
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

static int hwr_wtd_access(const char *path, int mode) { hwr_wtd_world.access_calls++; return hwr_wtd_world.noaccess ? -1 : 0; }
static int create_test_socket() { return hwr_wtd_world.socket_fail ? -1 : 3; }
static int hwr_wtd_close(int fd) { hwr_wtd_world.closes++; return 0; }
static int hwr_wtd_prctl(int option, ...) { hwr_wtd_world.prctl_calls++; return 0; }
static int hwr_wtd_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
	hwr_wtd_world_t *x = &hwr_wtd_world;
	if (x->selfail) { if (++x->selfails > 1000) throw 1; errno = EBADF; return -1; }   /* 1: hang (the loop never ends on a failing select) */
	if (x->sel0 && !x->sel0_done) { x->sel0_done = 1; return 0; }
	if (x->recvfail && !x->recv_done) return 1;
	if (x->next < x->ndg) return 1;
	throw 2;   /* 2: every scripted datagram was consumed: end of the endless loop */
}
static ssize_t hwr_wtd_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *a, socklen_t *l)
{
	hwr_wtd_world_t *x = &hwr_wtd_world;
	if (x->recvfail && !x->recv_done) { x->recv_done = 1; return -1; }
	unsigned n = x->dglen[x->next] < len ? x->dglen[x->next] : (unsigned)len;
	memcpy(buf, x->dgbuf[x->next], n); x->next++;
	return n;
}
static int mgmt_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir)
{
	hwr_wtd_world_t *x = &hwr_wtd_world;
	int i = x->cb_calls++;
	if (i < HWR_WTD_MAXCB) { x->cb_ap[i] = ap_index; memcpy(x->cb_mac[i], sta_mac, 6); memcpy(x->cb_frame[i], frame, len < 128 ? len : 128); x->cb_len[i] = len; x->cb_type[i] = type; x->cb_dir[i] = dir; }
	return 0;
}
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define access hwr_wtd_access
#define close hwr_wtd_close
#define prctl hwr_wtd_prctl
#define select hwr_wtd_select
#define recvfrom hwr_wtd_recvfrom
#define PR_SET_NAME 15
#define wifi_dppTestFrameHandler hwr_wtd_dppTestFrameHandler

/* --- wifi_hal_dpp.c:3431-3532 --- */
static void *wifi_dppTestFrameHandler(void *arg)
{
    int sockfd;
    int ret;
    unsigned char msg[1024];
    wifi_test_command_id_t cmd;
    mac_address_t   bmac;
    unsigned char frame[1024];
	char interface_name[32];
    wifi_tlv_t *tlv;
    fd_set rfds;
    struct timeval tv;
    int retval, ap_index;
    bool exit = false;
	struct sockaddr_in saddr;
	socklen_t slen;

    wifi_dpp_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    if ((access("/nvram/wifiDppTest", R_OK)) != 0) {
        wifi_dpp_dbg_print("%s:%d: Not a debug build exiting\n", __func__, __LINE__);
        return NULL;
    }

	if ((sockfd = create_test_socket()) < 0) {
        wifi_dpp_dbg_print("%s:%d: Socket create failed\n", __func__, __LINE__);
        return NULL;

	}

    while (exit == false) {

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == 0) {
            continue;
        } else if (retval == -1) {
            /* ---------- start fix 7: a failing select (not an interrupted one) never ended the loop: the thread spun on the error at full speed. */
            if (errno != EINTR) {
                exit = true;
            }
            /* ---------- end fix 7 */
            continue;
        }

        if (FD_ISSET(sockfd, &rfds) == 0) {
            continue;
        }
    	wifi_dpp_dbg_print("%s:%d:Socket signaled Receiving data from socket\n", __func__, __LINE__);
        
        if ((ret = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&saddr, &slen)) < 0) {
            continue;
        }

		wifi_dpp_dbg_print("%s:%d: Received data: %d, select returned:%d\n", __func__, __LINE__, ret, retval);

        /* ---------- start fix 6: a datagram shorter than the signature was compared with stale bytes of the previous datagram, and get_tlv was given the whole datagram length although it starts after the 8-byte signature (read past msg, parse of stale TLVs). */
        if (ret < (int)sizeof(wifi_common_hal_test_signature)) {
            continue;
        }
        /* ---------- end fix 6 */

        if (memcmp(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature)) != 0) {
            continue;
        }

        wifi_dpp_dbg_print("%s:%d: Received test signature\n", __func__, __LINE__);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_cmd, ret - sizeof(wifi_common_hal_test_signature))) == NULL) {
            continue;
        }
        /* ---------- start fix 1: the TLV length (taken from the datagram) was used to copy into the 4-byte cmd without any check. */
        if (tlv->length != sizeof(cmd) || tlv->value + tlv->length > msg + ret) {
            continue;
        }
        /* ---------- end fix 1 */
        memcpy((unsigned char *)&cmd, tlv->value, tlv->length);

        switch (cmd) {
            case wifi_test_command_id_chirp:
			case wifi_test_command_id_reconf_auth_resp:
                wifi_dpp_dbg_print("%s:%d: Received chirp test command\n", __func__, __LINE__);
                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_vap_name, ret - sizeof(wifi_common_hal_test_signature))) == NULL) {
                    continue;
                }
                /* ---------- start fix 2: the TLV length was copied into interface_name[32] without a check (and the name was not NUL terminated for sscanf). */
                if (tlv->length >= sizeof(interface_name) || tlv->value + tlv->length > msg + ret) {
                    continue;
                }
                /* ---------- end fix 2 */
                memcpy(interface_name, tlv->value, tlv->length);
                /* ---------- start fix 2b */
                interface_name[tlv->length] = '\0';
                /* ---------- end fix 2b */
                /* ---------- start fix 3: a name that is not "ath<N>" left ap_index uninitialised and the frame was still delivered with it. */
                if (sscanf(interface_name, "ath%d", &ap_index) != 1) {
                    continue;
                }
                /* ---------- end fix 3 */

                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_sta_mac, ret - sizeof(wifi_common_hal_test_signature))) == NULL) {
                    continue;
                }
                /* ---------- start fix 4: the TLV length was copied into the 6-byte bmac without a check. */
                if (tlv->length != sizeof(bmac) || tlv->value + tlv->length > msg + ret) {
                    continue;
                }
                /* ---------- end fix 4 */
                memcpy(bmac, tlv->value, tlv->length);

                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_raw, ret - sizeof(wifi_common_hal_test_signature))) == NULL) {
                    continue;
                }
                /* ---------- start fix 5: the TLV length was copied into frame[1024] without checking that the TLV lies inside the received bytes (read past msg). */
                if (tlv->length > sizeof(frame) || tlv->value + tlv->length > msg + ret) {
                    continue;
                }
                /* ---------- end fix 5 */
                memcpy(frame, tlv->value, tlv->length);
                wifi_dpp_dbg_print("%s:%d: Calling mgmt frame receive\n", __func__, __LINE__);

                mgmt_frame_received_callback(ap_index, bmac, frame, tlv->length, WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
                break;

            default:
                break;
        }
    }

    close(sockfd);

	return NULL;
}

extern "C" void *hwr_sg_wifi_dppTestFrameHandler(void *arg) { return hwr_wtd_dppTestFrameHandler(arg); }

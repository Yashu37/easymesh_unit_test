/*
 * TEST CASES / CONSTRUCTOR: construct_levl_csi_publish
 * Caller-owned buffers: lcp_mac_buf (6-byte mac_address arg), lcp_csi_buf (the
 * packed wifi_csi_dev_t whose header[] the function fills) , lcp_ctrl_buf,
 * lcp_app_buf; the runner poisons the LCP_PAD tail of each.
 * Cases: bus_publish (fifo off), fifo_open_ok (fd -1, open succeeds, write),
 * fifo_open_fail (fd -1, open fails -> return), fifo_fd_ready (fd>=0 -> write),
 * null_app (nothing happens).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

unsigned char lcp_mac_buf[6 + LCP_PAD];
alignas(16) char lcp_csi_buf[sizeof(wifi_csi_dev_t) + LCP_PAD];
alignas(16) char lcp_ctrl_buf[sizeof(wifi_ctrl_t) + LCP_PAD];
alignas(16) char lcp_app_buf[sizeof(struct wifi_app) + LCP_PAD];
unsigned char lcp_sink[LCP_SINK_SZ];
char lcp_pub_name[128];
unsigned int lcp_pub_len, lcp_write_len;
int lcp_pub_calls, lcp_open_calls, lcp_write_calls, lcp_open_ret, lcp_null_app;

lv_lcp_test_case_t levl_csi_publish_suite[] = {
    /* name            fifo fd  open_ret null_app | pub open write hdr_ok */
    { "bus_publish",     0, -1,  -1,      0,        1,  0,   0,    1 },
    { "fifo_open_ok",    1, -1,   9,      0,        0,  1,   1,    1 },
    { "fifo_open_fail",  1, -1,  -1,      0,        0,  1,   0,    0 },
    { "fifo_fd_ready",   1,  7,  -1,      0,        0,  0,   1,    1 },
    { "null_app",        0, -1,  -1,      1,        0,  0,   0,    0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_levl_csi_publish_input(const lv_lcp_test_case_t *tc)
{
    memset(lcp_csi_buf, 0, sizeof(lcp_csi_buf));
    memset(lcp_ctrl_buf, 0, sizeof(lcp_ctrl_buf));
    memset(lcp_app_buf, 0, sizeof(lcp_app_buf));
    memset(lcp_sink, 0, sizeof(lcp_sink));
    memset(lcp_pub_name, 0, sizeof(lcp_pub_name));
    lcp_pub_len = lcp_write_len = 0;
    lcp_pub_calls = lcp_open_calls = lcp_write_calls = 0;
    lcp_open_ret = tc->open_ret; lcp_null_app = tc->null_app;

    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    memset(lcp_mac_buf, 0, sizeof(lcp_mac_buf));
    memcpy(lcp_mac_buf, mac, 6);

    wifi_csi_dev_t *d = (wifi_csi_dev_t *)lcp_csi_buf;
    memcpy(d->sta_mac, mac, 6);
    memset(d->csi.raw, 0x5A, sizeof(d->csi.raw));      /* recognisable csi payload */

    struct wifi_app *app = (struct wifi_app *)lcp_app_buf;
    app->data.u.levl.csi_over_fifo = tc->fifo ? true : false;
    app->data.u.levl.csi_fd = tc->fd;
}

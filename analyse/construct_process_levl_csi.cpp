/*
 * TEST CASES / CONSTRUCTOR: construct_process_levl_csi
 * Caller-owned buffers: lpc_app_buf (levl wifi_app) and lpc_csi_buf (the
 * wifi_csi_dev_t whose sta_mac is read); the runner poisons the LPC_PAD tail
 * of both. The sounding entry for AA:BB:CC:DD:EE:01 is a heap block.
 * Cases: map_null, not_subscribed, interval_zero (always publish),
 * timeout_elapsed (old last publish), not_elapsed (future last publish ->
 * no publish), entry_gone (publish drops the entry before the update).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lpc_app_buf[sizeof(struct wifi_app) + LPC_PAD];
alignas(16) char lpc_csi_buf[sizeof(wifi_csi_dev_t) + LPC_PAD];
int lpc_pub_calls, lpc_drop_on_publish;

lv_lpc_test_case_t process_levl_csi_suite[] = {
    /* name             map_null slot interval last_off drop | ret pub updated */
    { "map_null",          1,     0,    0,      0,     0,     -1,  0,  0 },
    { "not_subscribed",    0,     0,    0,      0,     0,      0,  0,  0 },
    { "interval_zero",     0,     1,    0,     -5,     0,      0,  1,  1 },
    { "timeout_elapsed",   0,     1,  500,   -100,     0,      0,  1,  1 },
    { "not_elapsed",       0,     1,  500,   1000,     0,      0,  0,  0 },
    { "entry_gone",        0,     1,    0,     -5,     1,      0,  1,  0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_process_levl_csi_input(const lv_lpc_test_case_t *tc)
{
    memset(lpc_app_buf, 0, sizeof(lpc_app_buf));
    memset(lpc_csi_buf, 0, sizeof(lpc_csi_buf));
    lpc_pub_calls = 0; lpc_drop_on_publish = tc->drop;

    struct wifi_app *app = (struct wifi_app *)lpc_app_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.curr_sounding_mac_map = tc->map_null ? NULL : (void *)lpc_app_buf;   /* non-NULL token */

    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    memcpy(((wifi_csi_dev_t *)lpc_csi_buf)->sta_mac, mac, 6);
    lpc_set_slot(tc->slot ? mac : NULL, tc->interval, tc->last_off);
}

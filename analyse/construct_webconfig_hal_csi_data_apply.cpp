/*
 * TEST CASES / CONSTRUCTOR: construct_webconfig_hal_csi_data_apply
 * apps at whc_apps_buf (data.u.csi_analytics.csi_session_index set); the
 * decoded data at whc_dec_buf with a csi_data_queue of whc_count csi_data_t
 * entries. Cases exercise: NULL queue (early return), own-session skip,
 * disabled skip, a few enabled clients, and MANY clients (push total_str_mac
 * toward the MAX_MACLIST_SIZE guard in add_str_mac_addr).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#define CSI_CLIENT_PER_SESSION 64
typedef struct { unsigned long csi_session_num; bool enabled; unsigned int csi_client_count; unsigned char csi_client_list[CSI_CLIENT_PER_SESSION][6]; } csi_data_t_c;

char   whc_slot_mac[WHC_MAC_SZ + WHC_PAD];
char   whc_result[600];
unsigned int whc_count;
void  *whc_items[8];
int    whc_update_calls;
int    whc_null_queue;
alignas(16) char whc_apps_buf[sizeof(wifi_app_t) + WHC_PAD];
alignas(16) char whc_dec_buf[sizeof(void*) + WHC_PAD];
static csi_data_t_c whc_sess[4];

webconfig_hal_csi_data_apply_test_case_t webconfig_hal_csi_data_apply_suite[] = {
    /* name            null_queue  nsess  clients_each  expect_update */
    { "null_queue",     1,         0,     0,            0 },
    { "own_session",    0,         1,     0,            1 },   /* session matches -> skip clients */
    { "disabled",       0,         1,     0,            1 },
    { "few_clients",    0,         1,     3,            1 },
    { "many_clients",   0,         2,     30,           1 },   /* 60 macs -> near the 512 guard */
    { NULL, 0, 0, 0, 0 }
};

void construct_webconfig_hal_csi_data_apply_input(const webconfig_hal_csi_data_apply_test_case_t *tc)
{
    memset(whc_apps_buf, 0, sizeof(whc_apps_buf));
    memset(whc_dec_buf, 0, sizeof(whc_dec_buf));
    memset(whc_sess, 0, sizeof(whc_sess));
    wifi_app_t *app = (wifi_app_t *)whc_apps_buf;
    app->data.u.csi_analytics.csi_session_index = 100;   /* own session id */

    whc_null_queue = tc->null_queue;
    whc_count = tc->nsess;
    for (unsigned int k = 0; k < tc->nsess && k < 4; k++) {
        csi_data_t_c *d = &whc_sess[k];
        d->enabled = strcmp(tc->test_name, "disabled") != 0;
        d->csi_session_num = strcmp(tc->test_name, "own_session") == 0 ? 100 : (200 + k);
        d->csi_client_count = tc->clients_each;
        for (unsigned int c = 0; c < tc->clients_each && c < CSI_CLIENT_PER_SESSION; c++)
            for (int b = 0; b < 6; b++) d->csi_client_list[c][b] = (unsigned char)(0x10 + k*0x20 + c);  /* distinct macs */
        whc_items[k] = d;
    }
    whc_update_calls = 0; whc_result[0] = 0;
}

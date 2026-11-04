/*
 * TEST CASES / CONSTRUCTOR: construct_levl_get_handler
 * Caller-owned buffers: lgh_ctrl_buf (wifi_ctrl_t), lgh_app_buf (levl
 * wifi_app), lgh_pdata_buf (the raw_data_t out parameter) and lgh_name_buf
 * (the event_name string, sized EXACTLY strlen+1 so any over-read of the name
 * runs into the poisoned tail); the runner poisons the LGH_PAD tail of each.
 *
 * Cases: the four properties (clientMac / maxNumberCSIClients / Duration /
 * clientMacData) with zero and non-zero stored values, unknown property,
 * 199-char and 250-char property names (%199s truncates -> fits the 200-byte
 * array), no_prefix name, null name / ctrl / app, malloc failure on both
 * string properties.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lgh_ctrl_buf[sizeof(wifi_ctrl_t) + LGH_PAD];
alignas(16) char lgh_app_buf[sizeof(struct wifi_app) + LGH_PAD];
alignas(16) char lgh_pdata_buf[LGH_PDATA_SZ + LGH_PAD];
alignas(16) char lgh_name_buf[LGH_NAME_MAX + LGH_PAD];
size_t lgh_name_len;
int lgh_null_ctrl, lgh_null_app, lgh_malloc_fail, lgh_null_name;

#define P "Device.WiFi.X_RDK_CSI_LEVL."
#define L199 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define L250 L199 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
/* bus_error: 0 success, 1 general, 2 invalid_input, 3 out_of_resources; data_type: 3 string, 7 uint32 */
lv_lgh_test_case_t levl_get_handler_suite[] = {
    /* name              nc na nn mf  event_name             max dur | ret type u32  str */
    { "client_mac",       0, 0, 0, 0, P "clientMac",           0,   0,   0,  3,   0, "00:00:00:00:00:00" },
    { "max_zero",         0, 0, 0, 0, P "maxNumberCSIClients", 0,   0,   0,  7,   5, NULL },
    { "max_set",          0, 0, 0, 0, P "maxNumberCSIClients", 9,   0,   0,  7,   9, NULL },
    { "duration_zero",    0, 0, 0, 0, P "Duration",            0,   0,   0,  7,2000, NULL },
    { "duration_set",     0, 0, 0, 0, P "Duration",            0, 750,   0,  7, 750, NULL },
    { "client_mac_data",  0, 0, 0, 0, P "clientMacData",       0,   0,   0,  3,   0, " " },
    { "unknown_param",    0, 0, 0, 0, P "somethingElse",       0,   0,   0, -1,   0, NULL },
    { "param_199",        0, 0, 0, 0, P L199,                  0,   0,   0, -1,   0, NULL },
    { "param_250",        0, 0, 0, 0, P L250,                  0,   0,   0, -1,   0, NULL },
    { "no_prefix",        0, 0, 0, 0, "Other.Thing",           0,   0,   0, -1,   0, NULL },
    { "null_name",        0, 0, 1, 0, NULL,                    0,   0,   2, -1,   0, NULL },
    { "null_ctrl",        1, 0, 0, 0, P "clientMac",           0,   0,   1, -1,   0, NULL },
    { "null_app",         0, 1, 0, 0, P "clientMac",           0,   0,   1, -1,   0, NULL },
    { "malloc_fail_mac",  0, 0, 0, 1, P "clientMac",           0,   0,   3, -1,   0, NULL },
    { "malloc_fail_data", 0, 0, 0, 1, P "clientMacData",       0,   0,   3, -1,   0, NULL },
    { NULL, 0,0,0,0, NULL, 0,0,0,0,0, NULL }  /* sentinel */
};

void construct_levl_get_handler_input(const lv_lgh_test_case_t *tc)
{
    memset(lgh_ctrl_buf, 0, sizeof(lgh_ctrl_buf));
    memset(lgh_app_buf, 0, sizeof(lgh_app_buf));
    memset(lgh_pdata_buf, 0, sizeof(lgh_pdata_buf));
    memset(lgh_name_buf, 0, sizeof(lgh_name_buf));
    lgh_null_ctrl = tc->null_ctrl; lgh_null_app = tc->null_app;
    lgh_malloc_fail = tc->malloc_fail; lgh_null_name = tc->null_name;

    struct wifi_app *app = (struct wifi_app *)lgh_app_buf;
    app->data.u.levl.max_num_csi_clients = tc->max_clients;
    app->data.u.levl.sounding_duration = tc->duration;

    lgh_name_len = 0;
    if (tc->name) {
        lgh_name_len = strlen(tc->name) + 1;
        memcpy(lgh_name_buf, tc->name, lgh_name_len);
    }
}

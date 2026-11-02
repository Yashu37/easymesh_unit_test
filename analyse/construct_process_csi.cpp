/*
 * TEST CASES / CONSTRUCTOR: construct_process_csi
 * mac_addr is a 6-byte buffer at pcs_mac_buf (runner poisons past 6). The CSI
 * map entry (pcs_entry) is present/absent and MLO/non-MLO. ctrl/app can be NULL.
 * Cases: no ctrl, no app, entry absent, entry non-MLO (result=mac_addr), entry
 * MLO (result=entry mac), hex MAC.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
typedef struct { bool is_mlo; unsigned char mac_addr[6]; } csi_mac_data_t_c;

char   pcs_slot_mac[PCS_MAC_SZ + PCS_PAD];
char   pcs_key_seen[64];
int    pcs_ctrl_null;
void  *pcs_entry;
wifi_app_t *pcs_app;
alignas(16) char pcs_ctrl_buf[sizeof(wifi_ctrl_t) + PCS_PAD];
alignas(16) char pcs_app_buf[sizeof(wifi_app_t) + PCS_PAD];
alignas(16) unsigned char pcs_mac_buf[6 + PCS_PAD];
alignas(16) char pcs_csi_buf[256 + PCS_PAD];     /* dummy csi_data (not derefed on NULL-event path) */
static csi_mac_data_t_c pcs_known;

process_csi_test_case_t process_csi_suite[] = {
    /* name          ctrl_null  app_null  have_entry  is_mlo  mac0  ret */
    { "no_ctrl",       1,        0,        0,          0,      0x10, -1 },
    { "no_app",        0,        1,        0,          0,      0x10, -1 },
    { "entry_absent",  0,        0,        0,          0,      0x10, -1 },
    { "entry_nonmlo",  0,        0,        1,          0,      0x10, -1 },  /* create_wifi_event NULL -> RETURN_ERR */
    { "entry_mlo",     0,        0,        1,          1,      0x10, -1 },
    { "mac_hex",       0,        0,        1,          0,      0xaa, -1 },
    { NULL, 0, 0, 0, 0, 0, 0 }
};

void construct_process_csi_input(const process_csi_test_case_t *tc)
{
    memset(pcs_ctrl_buf, 0, sizeof(pcs_ctrl_buf));
    memset(pcs_app_buf, 0, sizeof(pcs_app_buf));
    memset(pcs_mac_buf, 0, sizeof(pcs_mac_buf));
    memset(pcs_csi_buf, 0, sizeof(pcs_csi_buf));
    for (int b = 0; b < 6; b++) pcs_mac_buf[b] = (unsigned char)(tc->mac0 + b);

    wifi_app_t *app = (wifi_app_t *)pcs_app_buf;
    app->data.u.csi.csi_sounding_mac_map = (void *)0x1;
    pcs_app = tc->app_null ? NULL : app;
    pcs_ctrl_null = tc->ctrl_null;

    memset(&pcs_known, 0, sizeof(pcs_known));
    pcs_known.is_mlo = tc->is_mlo ? true : false;
    for (int b = 0; b < 6; b++) pcs_known.mac_addr[b] = 0xE0 + b;   /* distinct from mac_addr */
    pcs_entry = tc->have_entry ? &pcs_known : NULL;
    pcs_key_seen[0] = 0;
}

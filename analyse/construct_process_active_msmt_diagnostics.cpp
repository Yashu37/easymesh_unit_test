/*
 * TEST CASES / CONSTRUCTOR: construct_process_active_msmt_diagnostics
 *
 * The g_active_msmt stand-in holds curStepData.DestMac (13-byte MAC),
 * active_msmt.ActiveMsmtNumberOfSamples, active_msmt_map, and the source
 * active_msmt_data array (pad_src_samples, sized to the sample count).
 * An "existing" station may be pre-registered under the lower-case key.
 *
 * Cases: NULL map (early return), new offline client (ap_index -1, calloc),
 * new online client (ap_index 5) with 3 samples copied, existing station
 * updated, zero samples (loop skipped), and a MAC with hex letters.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   pad_slot_key[PAD_KEY_SZ + PAD_PAD];
size_t pad_key_len;
char   pad_key_seen[64];
char   pad_put_key[64];
void  *pad_put_data;
void  *pad_existing;
char   pad_existing_key[32];
int    pad_calls;
alignas(16) char pad_mgr_buf[sizeof(wifi_actvie_msmt_t) + PAD_PAD];
alignas(16) char pad_src_buf[PAD_MAX_SAMPLES * sizeof(active_msmt_data_t) + PAD_PAD];
static blaster_hashmap_t pad_known;

process_active_msmt_diagnostics_test_case_t process_active_msmt_diagnostics_suite[] = {
    /* name              no_map ap_index samples existing mac0  expect_put */
    { "null_map",          1,    5,       0,      0,      0x10,  0 },
    { "new_offline",       0,   -1,       3,      0,      0x10,  1 },
    { "new_online_3",      0,    5,       3,      0,      0x10,  1 },
    { "existing_online",   0,    5,       2,      1,      0x10,  0 },
    { "zero_samples",      0,    5,       0,      0,      0x10,  1 },
    { "mac_hex_letters",   0,    5,       1,      0,      0xaa,  1 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

static char pad_mgr_mutex_init;

void construct_process_active_msmt_diagnostics_input(const process_active_msmt_diagnostics_test_case_t *tc)
{
    memset(pad_mgr_buf, 0, sizeof(pad_mgr_buf));
    memset(pad_src_buf, 0, sizeof(pad_src_buf));
    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)pad_mgr_buf;
    pthread_mutex_init(&g->lock, NULL);

    for (int b = 0; b < 6; b++)
        g->curStepData.DestMac[b] = (unsigned char)(tc->mac0 + b);
    g->active_msmt.ActiveMsmtNumberOfSamples = tc->samples;
    g->active_msmt_map = tc->no_map ? NULL : (void *)0x1;   /* only passed to the stubs */

    if (tc->samples > 0) {
        active_msmt_data_t *src = (active_msmt_data_t *)pad_src_buf;
        for (unsigned int i = 0; i < tc->samples; i++) {
            src[i].rssi = -40 - (int)i;
            src[i].TxPhyRate = 100 + i;
            snprintf(src[i].Operating_standard, OPER_BUFFER_LEN, "11ax");
            snprintf(src[i].Operating_channelwidth, OPER_BUFFER_LEN, "80MHz");
        }
        g->active_msmt_data = src;
    } else {
        g->active_msmt_data = NULL;
    }

    /* existing station keyed by the lower-case MAC string */
    memset(&pad_known, 0, sizeof(pad_known));
    pad_existing = tc->existing ? &pad_known : NULL;
    snprintf(pad_existing_key, sizeof(pad_existing_key), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)tc->mac0, (unsigned char)(tc->mac0+1), (unsigned char)(tc->mac0+2),
             (unsigned char)(tc->mac0+3), (unsigned char)(tc->mac0+4), (unsigned char)(tc->mac0+5));

    pad_key_len = 0;
    pad_key_seen[0] = 0;
    pad_put_key[0] = 0;
    pad_put_data = NULL;
    pad_calls = 0;
    (void)pad_mgr_mutex_init;
}

/*
 * HANDLER: wifi_hal_set_acs_keep_out_chans (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-2): src/wifi_hal.c:1893-1924 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fixes 1-2 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  It builds the ACS exclusion string in the local
 * buff[ACS_MAX_VECTOR_LEN + 2] (ACS_MAX_VECTOR_LEN = 256 * 7: room for 256 chanspecs): for every bandwidth with num_channels_list != 0 and every channel list j < num_channels_list it calls
 * wifi_drv_get_chspc_configs(radioIndex, bandwidth, &channels_list[j], buff), which appends the chanspecs of that list to buff (no size argument), then removes the trailing comma and hands the string to
 * wifi_drv_set_acs_exclusion_list(); a NULL parameter clears the list.  num_channels_list is not checked against the channels_list array (MAX_CHANNELS = 64) and the length of buff is never checked.
 *
 * Scaffolding only: wifi_drv_get_chspc_configs is a stand-in with the behaviour of the Broadcom hook (strcat of "0x%04x," per channel, reading at most MAX_CHANNELS channels of the list), wifi_drv_set_acs_exclusion_list
 * records its argument; ACS_MAX_VECTOR_LEN is the value of src/wifi_hal_priv.h:234; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_set_acs_keep_out_chans.
 */
#include "hwr_wak.h"
#include <stdio.h>
#include <string.h>

#define ACS_MAX_VECTOR_LEN  (256 * 7)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define wifi_drv_get_chspc_configs hwr_wak_wifi_drv_get_chspc_configs
#define wifi_drv_set_acs_exclusion_list hwr_wak_wifi_drv_set_acs_exclusion_list
#define wifi_hal_set_acs_keep_out_chans hwr_sg_wifi_hal_set_acs_keep_out_chans

hwr_wak_world_t hwr_wak_world;

extern "C" {
int wifi_drv_get_chspc_configs(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, const wifi_channels_list_t *chanlist, char *buff)
{
    hwr_wak_world_t *w = &hwr_wak_world;
    int n = chanlist->num_channels;                       /* the hook reads the list it is given */
    int c = w->get_calls++;
    if (c < 400) { w->seen_bw[c] = (int)bandwidth; w->seen_n[c] = n; }
    if (w->fail_at && w->get_calls == w->fail_at) return -1;
    for (int i = 0; i < n && i < MAX_CHANNELS; i++) {
        char one[16];
        snprintf(one, sizeof(one), "0x%04x,", (unsigned)(((int)bandwidth << 8) | (chanlist->channels_list[i] & 0xff)) & 0xffff);
        strcat(buff, one);                               /* as the Broadcom hook: no size limit */
    }
    return 0;
}
int wifi_drv_set_acs_exclusion_list(unsigned int radioIndex, char *buff)
{
    hwr_wak_world_t *w = &hwr_wak_world;
    w->set_calls++; w->set_radio = (int)radioIndex; w->set_null = (buff == NULL);
    if (buff) snprintf(w->set_str, sizeof(w->set_str), "%s", buff); else w->set_str[0] = 0;
    return w->set_ret;
}

/* --- wifi_hal.c:1893-1924 --- */
INT wifi_hal_set_acs_keep_out_chans(wifi_radio_operationParam_t *wifi_radio_oper_param,
    int radioIndex)
{
    char buff[ACS_MAX_VECTOR_LEN + 2];
    char excl_chan_string[20];
    memset(buff, 0, sizeof(buff));
    snprintf(excl_chan_string, sizeof(excl_chan_string), "wl%u_acs_excl_chans", radioIndex);
    if (!wifi_radio_oper_param) {
        wifi_hal_error_print("%s:%d Null radio operation parameter, hence clearing entries\n", __func__, __LINE__);
        return wifi_drv_set_acs_exclusion_list(radioIndex, NULL);
    }
    for (size_t i = 0; i < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; i++) {
        wifi_channels_list_per_bandwidth_t *chans_per_band = 
            &wifi_radio_oper_param->channels_per_bandwidth[i];
        if (chans_per_band->num_channels_list == 0) {
            continue;
        }
        wifi_channelBandwidth_t bandwidth = chans_per_band->chanwidth;
        /* ---------- start fix 1: num_channels_list was not checked against the channels_list array, so a value above
         * MAX_CHANNELS read list entries past the array (and past the parameter). */
        if (chans_per_band->num_channels_list > MAX_CHANNELS) {
            wifi_hal_error_print("%s:%d Invalid num_channels_list %d for bandwidth 0x%x\n",
                               __func__, __LINE__, chans_per_band->num_channels_list, bandwidth);
            return RETURN_ERR;
        }
        /* ---------- end fix 1 */
        for (int j = 0; j < chans_per_band->num_channels_list; j++) {
            /* ---------- start fix 2: the platform hook appends up to 7 bytes ("0x%04x,") per channel to buff with
             * strcat and no size argument; refuse a list that would not fit in the remaining space of buff. */
            if (chans_per_band->channels_list[j].num_channels < 0 ||
                chans_per_band->channels_list[j].num_channels > MAX_CHANNELS ||
                strlen(buff) + 7 * (size_t)chans_per_band->channels_list[j].num_channels + 1 > sizeof(buff)) {
                wifi_hal_error_print("%s:%d Chanspec list for radio %u bandwidth 0x%x does not fit in buff\n",
                                   __func__, __LINE__, radioIndex, bandwidth);
                return RETURN_ERR;
            }
            /* ---------- end fix 2 */
            if (wifi_drv_get_chspc_configs(radioIndex, bandwidth, &chans_per_band->channels_list[j], buff) != 0) {
                wifi_hal_error_print("%s:%d Failed for radio %u bandwidth 0x%x\n",
                                   __func__, __LINE__, radioIndex, bandwidth);
                return RETURN_ERR;
            }
        }
    }
    size_t len = strlen(buff);
    if (len > 0) {
        buff[len - 1] = '\0';
    }
    return wifi_drv_set_acs_exclusion_list(radioIndex, buff);
}
}

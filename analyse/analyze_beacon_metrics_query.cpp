/*
 * HANDLER: analyze_beacon_metrics_query
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529). No fixes. Local array: bssid_mac[6] (unsigned int) filled
 * by sscanf and copied to beacon_params->bssid[0..5]. It also fills the
 * caller-owned evt->params beacon struct: ssid[32] (strnlen 31 + NUL),
 * ap_channel_rprt[EM_MAX_NEIGHBORS=16] (index < num_ap_channel_rprt, checked),
 * ap_channel_list[64] (j < chlist_count, checked) and element_list[32].
 *
 * Poison lives ONLY in the runner (analyze_beacon_metrics_query_test.cpp).
 * Scaffolding only stubs the cmd / dm classes (not under test). The real
 * dm_easy_mesh_t::string_to_macbytes is copied verbatim into the dm stub.
 * Everything lives in namespace abq so the real-size beacon types (element_list
 * [32]) do not clash with common.h's trimmed copies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace abq {

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))
#endif

/* --- scaffolding --- */
class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }   /* src/cmd/em_cmd.cpp returns NULL */
};
em_cmd_beacon_metrics_param_t last_params;
int cmd_created = 0;
class dm_easy_mesh_t {
public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
};
class em_cmd_beacon_query_t : public em_cmd_t {
public:
    em_cmd_beacon_query_t(em_cmd_params_t param, dm_easy_mesh_t &dm)
    {
        (void)dm;
        memcpy(&last_params, &param.u.beacon_metrics_params, sizeof(last_params));
        cmd_created++;
    }
};
class dm_easy_mesh_ctrl_t {
public:
    operator dm_easy_mesh_t() { return dm_easy_mesh_t(); }
    int analyze_beacon_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};

/* copied verbatim from src/dm/dm_easy_mesh.cpp */
void dm_easy_mesh_t::string_to_macbytes(char *key, mac_address_t bmac)
{
    unsigned char mac[6];
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
int dm_easy_mesh_ctrl_t::analyze_beacon_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_easy_mesh_t dm = *this;
    em_subdoc_info_t *subdoc;
    cJSON *root, *wfa_obj, *net_obj;
    cJSON *dev_arr, *dev_obj;
    cJSON *radio_arr, *radio_obj;
    cJSON *bss_arr, *bss_obj;
    cJSON *sta_arr, *sta_obj;
    cJSON *bmquery_obj, *mac_obj, *op_class_obj, *channel_obj, *bssid_obj, *rprt_obj, *ssid_obj;
    cJSON *chrep_arr, *chrep_obj, *chlist_arr, *chlist_obj, *elemlist_arr, *elemlist_obj;
    int num = 0;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;
    root = cJSON_Parse(subdoc->buff);
    if (root == NULL) {
        return 0;
    }

    if ((wfa_obj = cJSON_GetObjectItem(root, "wfa-dataelements:BeaconMetricsQuery")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if ((net_obj = cJSON_GetObjectItem(wfa_obj, "Network")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }

    if ((dev_arr = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_GetArraySize(dev_arr) == 0 || (dev_obj = cJSON_GetArrayItem(dev_arr, 0)) == NULL) {
        cJSON_Delete(root);
        return 0;
    }

    if ((radio_arr = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_GetArraySize(radio_arr) == 0 || (radio_obj = cJSON_GetArrayItem(radio_arr, 0)) == NULL) {
        cJSON_Delete(root);
        return 0;
    }

    if ((bss_arr = cJSON_GetObjectItem(radio_obj, "BSSList")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_GetArraySize(bss_arr) == 0 || (bss_obj = cJSON_GetArrayItem(bss_arr, 0)) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if ((sta_arr = cJSON_GetObjectItem(bss_obj, "STAList")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_GetArraySize(sta_arr) == 0 || (sta_obj = cJSON_GetArrayItem(sta_arr, 0)) == NULL) {
        cJSON_Delete(root);
        return 0;
    }

    em_cmd_beacon_metrics_param_t *beacon_params = &evt->params.u.beacon_metrics_params;

    if ((mac_obj = cJSON_GetObjectItem(sta_obj, "MACAddress")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    char *sta_mac_str = cJSON_GetStringValue(mac_obj);
    if (!sta_mac_str) {
        cJSON_Delete(root);
        return 0;
    }
    dm_easy_mesh_t::string_to_macbytes(sta_mac_str, beacon_params->sta_mac_addr);

    if ((bmquery_obj = cJSON_GetObjectItem(sta_obj, "BeaconMetricsQuery")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    if ((op_class_obj = cJSON_GetObjectItem(bmquery_obj, "OperatingClass")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    beacon_params->op_class = static_cast<unsigned char> (cJSON_GetNumberValue(op_class_obj));

    if ((channel_obj = cJSON_GetObjectItem(bmquery_obj, "Channel")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    beacon_params->channel_num = static_cast<unsigned char> (cJSON_GetNumberValue(channel_obj));

    if ((bssid_obj = cJSON_GetObjectItem(bmquery_obj, "BSSID")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    char *bssid_str = cJSON_GetStringValue(bssid_obj);
    if (!bssid_str) {
        cJSON_Delete(root);
        return 0;
    }
    unsigned int bssid_mac[6] = {0};
    int bssid_parsed = (strchr(bssid_str, ':') != NULL) ?
        sscanf(bssid_str, "%02x:%02x:%02x:%02x:%02x:%02x", &bssid_mac[0], &bssid_mac[1], &bssid_mac[2], &bssid_mac[3], &bssid_mac[4], &bssid_mac[5]) :
        sscanf(bssid_str, "%02x%02x%02x%02x%02x%02x", &bssid_mac[0], &bssid_mac[1], &bssid_mac[2], &bssid_mac[3], &bssid_mac[4], &bssid_mac[5]);
    if (bssid_parsed != 6) {
        em_printfout("Invalid BSSID MAC string: %s", bssid_str);
        cJSON_Delete(root);
        return 0;
    }
    for (int b = 0; b < 6; b++) {
        beacon_params->bssid[b] = static_cast<unsigned char>(bssid_mac[b]);
    }

    if ((rprt_obj = cJSON_GetObjectItem(bmquery_obj, "ReportingDetail")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    beacon_params->rprt_detail = static_cast<unsigned char> (cJSON_GetNumberValue(rprt_obj));
    if (beacon_params->rprt_detail > 2) {
        cJSON_Delete(root);
        return 0;
    }

    if ((ssid_obj = cJSON_GetObjectItem(bmquery_obj, "SSID")) == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    const char *ssid_str = cJSON_GetStringValue(ssid_obj);
    if (!ssid_str) {
        cJSON_Delete(root);
        return 0;
    }
    size_t ssid_len = strnlen(ssid_str, sizeof(beacon_params->ssid) - 1U);
    beacon_params->ssid_len = static_cast<unsigned char> (ssid_len);
    memcpy(beacon_params->ssid, ssid_str, ssid_len);
    beacon_params->ssid[ssid_len] = '\0';


    if (beacon_params->channel_num == 255) {
        if ((chrep_arr = cJSON_GetObjectItem(bmquery_obj, "APChReportList")) == NULL) {
            cJSON_Delete(root);
            return 0;
        }
        beacon_params->num_ap_channel_rprt = static_cast<unsigned char> (cJSON_GetArraySize(chrep_arr));
        if (!beacon_params->num_ap_channel_rprt ||
            (beacon_params->num_ap_channel_rprt > ARRAY_SIZE(beacon_params->ap_channel_rprt))) {
            cJSON_Delete(root);
            return 0;
        }
        for (int i = 0; i < beacon_params->num_ap_channel_rprt; i++) {
            if ((chrep_obj = cJSON_GetArrayItem(chrep_arr, i)) == NULL) {
                cJSON_Delete(root);
                return 0;
            }
            if ((op_class_obj = cJSON_GetObjectItem(chrep_obj, "OpClass")) == NULL) {
                cJSON_Delete(root);
                return 0;
            }
            beacon_params->ap_channel_rprt[i].ap_channel_op_class =
                static_cast<unsigned char> (cJSON_GetNumberValue(op_class_obj));

            if ((chlist_arr = cJSON_GetObjectItem(chrep_obj, "ChannelList")) == NULL) {
                cJSON_Delete(root);
                return 0;
            }
            unsigned int chlist_count = static_cast<unsigned int> (cJSON_GetArraySize(chlist_arr));
            if (!chlist_count ||
                (chlist_count > ARRAY_SIZE(beacon_params->ap_channel_rprt[i].ap_channel_list))) {
                cJSON_Delete(root);
                return 0;
            }
            // Wire format includes the 1-byte operating class in this length
            // (see em_agent.cpp:1205's "- 1" when consuming this same field).
            beacon_params->ap_channel_rprt[i].ap_channel_rprt_len =
                static_cast<unsigned char> (chlist_count + 1);

            for (unsigned int j = 0; j < chlist_count; j++) {
                if ((chlist_obj = cJSON_GetArrayItem(chlist_arr, static_cast<int>(j))) == NULL) {
                    cJSON_Delete(root);
                    return 0;
                }
                beacon_params->ap_channel_rprt[i].ap_channel_list[j] =
                    static_cast<unsigned char> (cJSON_GetNumberValue(chlist_obj));
            }
        }
    } else {
        beacon_params->num_ap_channel_rprt = 0;
        memset(beacon_params->ap_channel_rprt, 0, sizeof(beacon_params->ap_channel_rprt));
    }

    if (beacon_params->rprt_detail == 1) {
        if ((elemlist_arr = cJSON_GetObjectItem(bmquery_obj, "ElementList")) == NULL) {
            cJSON_Delete(root);
            return 0;
        }
        beacon_params->element_list.num_element_id = static_cast<unsigned char> (cJSON_GetArraySize(elemlist_arr));
        if (!beacon_params->element_list.num_element_id ||
            (beacon_params->element_list.num_element_id > ARRAY_SIZE(beacon_params->element_list.element_list))) {
            cJSON_Delete(root);
            return 0;
        }

        for (int i = 0; i < beacon_params->element_list.num_element_id; i++) {
            if ((elemlist_obj = cJSON_GetArrayItem(elemlist_arr, i)) == NULL) {
                cJSON_Delete(root);
                return 0;
            }
            beacon_params->element_list.element_list[i] = static_cast<unsigned char> (cJSON_GetNumberValue(elemlist_obj));
        }
    } else {
        beacon_params->element_list.num_element_id = 0;
        memset(&beacon_params->element_list, 0, sizeof(beacon_params->element_list));
    }

    cJSON_Delete(root);

    pcmd[num] = new em_cmd_beacon_query_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

/* --- runner entry point --- */
int invoke(em_bus_event_t *evt, void **pcmd)
{
    static dm_easy_mesh_ctrl_t ctrl;
    cmd_created = 0;
    memset(&last_params, 0, sizeof(last_params));
    int n = ctrl.analyze_beacon_metrics_query(evt, reinterpret_cast<em_cmd_t **>(pcmd));
    for (int i = 0; i < n; i++) { delete static_cast<em_cmd_t *>(pcmd[i]); pcmd[i] = NULL; }  /* free stub cmds (harness only) */
    return n;
}

} /* namespace abq */

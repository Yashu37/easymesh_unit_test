/*
 * HANDLER: analyze_unassoc_sta_metrics_query
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::analyze_unassoc_sta_metrics_query. No fixes. Local
 * arrays: wfa[128], al_mac_buf[32] (strncpy bounded), the on-stack em_unassoc_query_list_t query
 * (opclass_list[64], channel_list[16], sta_list[64]; the loops cap opclass_count at EM_MAX_OP_CLASS 48,
 * channel_count at 16, sta_count at 64) and pcmd[num]. Real cJSON; dm_easy_mesh_t::string_to_macbytes()
 * (src/dm/dm_easy_mesh.cpp) is copied verbatim.
 * Scaffolding: the caller-owned event (uaq::evt_buf, runner poisons past the subdoc NUL and the event's
 * guard field) and pcmd array (runner poisons slot 16 onward); em_cmd_unassoc_sta_query_t only records
 * the query it is given (summarised into g_sum).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include "analyze_unassoc_sta_metrics_query.h"

namespace uaq {

int g_num = 0;
char g_sum[4096];
static int g_cmds = 0;

class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }    /* src/cmd/em_cmd.cpp returns NULL */
};
class dm_easy_mesh_t {
public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
};
static void summarise(em_cmd_params_t *p, em_unassoc_query_list_t *q)
{
    char *s = g_sum; size_t n = sizeof(g_sum);
    unsigned char *a = p->u.unassoc_sta_query_params.al_mac;
    int w = snprintf(s, n, "al=%02x:%02x:%02x:%02x:%02x:%02x nop=%d", a[0], a[1], a[2], a[3], a[4], a[5], q->num_opclass);
    s += w; n -= w;
    for (int i = 0; i < q->num_opclass && i < 3; i++) {
        em_unassoc_query_opclass_t *o = &q->opclass_list[i];
        w = snprintf(s, n, " oc%d=%d/%d", i, o->op_class, o->num_channels); s += w; n -= w;
        for (int j = 0; j < o->num_channels && j < 3; j++) {
            em_unassoc_query_channel_t *c = &o->channel_list[j];
            w = snprintf(s, n, " c%d.%d=%d/%d", i, j, c->channel, c->num_sta); s += w; n -= w;
            for (int k = 0; k < c->num_sta && k < 3; k++) {
                unsigned char *m = c->sta_list[k];
                w = snprintf(s, n, " s%d.%d.%d=%02x:%02x:%02x:%02x:%02x:%02x", i, j, k, m[0], m[1], m[2], m[3], m[4], m[5]); s += w; n -= w;
            }
        }
    }
}
class em_cmd_unassoc_sta_query_t : public em_cmd_t {
public:
    em_cmd_unassoc_sta_query_t(em_cmd_params_t param, dm_easy_mesh_t &dm, em_unassoc_query_list_t *query)
    { (void)dm; g_cmds++; summarise(&param, query); }
};
class dm_easy_mesh_ctrl_t {
public:
    operator dm_easy_mesh_t() { return dm_easy_mesh_t(); }
    int analyze_unassoc_sta_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};
static dm_easy_mesh_ctrl_t g_ctrl;

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
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
int dm_easy_mesh_ctrl_t::analyze_unassoc_sta_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int num = 0;
    em_cmd_t *tmp = NULL;
    em_subdoc_info_t *subdoc = NULL;

    cJSON *obj = NULL;
    cJSON *wfa_obj = NULL;

    cJSON *al_mac_obj = NULL;
    cJSON *query_list = NULL;

    char wfa[128] = {0};

    subdoc = &evt->u.subdoc;
    if (subdoc == NULL) {
        em_printfout("subdoc NULL");
        return 0;
    }

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        em_printfout("JSON parse failed");
        return 0;
    }

    snprintf(wfa, sizeof(wfa), "wfa-dataelements:UnassocSTAQuery");

    wfa_obj = cJSON_GetObjectItem(obj, wfa);

    if (wfa_obj == NULL) {
        em_printfout("Missing wfa object");
        cJSON_Delete(obj);
        return 0;
    }

    al_mac_obj = cJSON_GetObjectItem(wfa_obj, "AlMac");

    query_list = cJSON_GetObjectItem(wfa_obj, "UnassocStaQueryList");

    if ((al_mac_obj == NULL) || (query_list == NULL) || (!cJSON_IsArray(query_list))) {
        em_printfout("Missing mandatory params");
        cJSON_Delete(obj);
        return 0;
    }

    em_cmd_params_t params = evt->params;

    const char *al_mac_str = cJSON_GetStringValue(al_mac_obj);
    if (al_mac_str == NULL) {
        em_printfout("%s:%d: AlMac is not a string", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }

    char al_mac_buf[32] = {0};
    strncpy(al_mac_buf, al_mac_str, sizeof(al_mac_buf) - 1);

    dm_easy_mesh_t::string_to_macbytes(al_mac_buf, params.u.unassoc_sta_query_params.al_mac);

    // dm_easy_mesh_ctrl_t is not a dm_easy_mesh_t; this constructs one via
    // the dm_network_t converting constructor, not the (deleted) copy ctor
    dm_easy_mesh_t dm = *this;

    em_unassoc_query_list_t query;
    memset(&query, 0, sizeof(query));

    int opclass_count = cJSON_GetArraySize(query_list);

    if (opclass_count > EM_MAX_OP_CLASS) {
        opclass_count = EM_MAX_OP_CLASS;
    }

    query.num_opclass = static_cast<uint8_t>(opclass_count);

    for (int i = 0; i < opclass_count; i++) {

        cJSON *opclass_obj = cJSON_GetArrayItem(query_list, i);

        if (opclass_obj == NULL) {
            continue;
        }

        cJSON *opclass_val = cJSON_GetObjectItem(opclass_obj, "opclass");

        cJSON *channels_array = cJSON_GetObjectItem(opclass_obj, "channels");

        if ((opclass_val == NULL) || (channels_array == NULL) || (!cJSON_IsArray(channels_array))) {
            continue;
        }

        auto &op = query.opclass_list[i];

        op.op_class = static_cast<uint8_t>(opclass_val->valueint);

        int channel_count = cJSON_GetArraySize(channels_array);

        if (channel_count > EM_MAX_CHANNELS_PER_OPCLASS) {
            channel_count = EM_MAX_CHANNELS_PER_OPCLASS;
        }

        op.num_channels = static_cast<uint8_t>(channel_count);

        for (int j = 0; j < channel_count; j++) {

            cJSON *channel_obj = cJSON_GetArrayItem(channels_array, j);

            if (channel_obj == NULL) {
                continue;
            }

            cJSON *channel_val = cJSON_GetObjectItem(channel_obj, "channel");
            cJSON *sta_array = cJSON_GetObjectItem(channel_obj, "sta_macs");

            if ((channel_val == NULL) || (sta_array == NULL) || (!cJSON_IsArray(sta_array))) {
                continue;
            }

            auto &ch = op.channel_list[j];

            ch.channel = static_cast<uint8_t>(channel_val->valueint);

            int sta_count = cJSON_GetArraySize(sta_array);

            if (sta_count > EM_MAX_STA_PER_CHANNEL) {
                sta_count = EM_MAX_STA_PER_CHANNEL;
            }

            ch.num_sta = static_cast<uint8_t>(sta_count);

            for (int k = 0; k < sta_count; k++) {
                cJSON *sta_obj = cJSON_GetArrayItem(sta_array, k);

                if ((sta_obj == NULL) || (sta_obj->valuestring == NULL)) {
                    continue;
                }

                dm_easy_mesh_t::string_to_macbytes(sta_obj->valuestring, ch.sta_list[k]);
            }
        }
    }

    pcmd[num] = new em_cmd_unassoc_sta_query_t(params, dm, &query);

    if (pcmd[num] == NULL) {
        cJSON_Delete(obj);
        return 0;
    }

    tmp = pcmd[num];
    num++;

    while ((pcmd[num] =
            tmp->clone_for_next()) != NULL) {

        tmp = pcmd[num];
        num++;
    }

    cJSON_Delete(obj);

    em_printfout("Returning successfully from analyze_unassoc_sta_metrics_query");

    return num;
}

int invoke(void)
{
    g_sum[0] = '\0';
    g_cmds = 0;
    memset(pcmd_buf, 0, UAQ_MAXCMD * sizeof(void *));
    g_num = g_ctrl.analyze_unassoc_sta_metrics_query((em_bus_event_t *)evt_buf, (em_cmd_t **)pcmd_buf);
    for (int i = 0; i < g_num; i++) delete (em_cmd_t *)pcmd_buf[i];
    return g_num;
}

} /* namespace uaq */

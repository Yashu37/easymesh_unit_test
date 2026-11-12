/*
 * HANDLER: analyze_client_assoc
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529). No fixes. Local arrays: mac[6] (two scopes, unsigned int)
 * filled by sscanf("%02x:..."/"%02x..", &mac[0..5]) and copied into
 * assoc_param.bssid / assoc_param.sta_list[i][k]. The caller-owned pcmd[] is
 * filled at pcmd[num] (num = 0 then clone_for_next chain), sta_list[] is
 * indexed by i < sta_count <= MAX_STA_LIST.
 *
 * Poison lives ONLY in the runner (analyze_client_assoc_test.cpp).
 * Scaffolding below only stubs the em_cmd / dm classes (not under test).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding: minimal stand-ins for the classes the function touches --- */
class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }   /* src/cmd/em_cmd.cpp: returns NULL */
};
em_cmd_client_assoc_params_t ac_last_params;              /* captured by the stub ctor */
int ac_cmd_created = 0;
class em_cmd_client_assoc_ctrl_req_t : public em_cmd_t {
public:
    em_cmd_client_assoc_ctrl_req_t(em_cmd_client_assoc_params_t params, dm_easy_mesh_t &dm)
    {
        (void)dm;
        memcpy(&ac_last_params, &params, sizeof(params));
        ac_cmd_created++;
    }
};
class dm_easy_mesh_ctrl_t {
public:
    /* real class converts to a dm_easy_mesh_t for `dm_easy_mesh_t dm = *this;` */
    operator dm_easy_mesh_t() { return dm_easy_mesh_t(); }
    int analyze_client_assoc(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
int dm_easy_mesh_ctrl_t::analyze_client_assoc(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    cJSON *obj, *wfa_obj;
    cJSON *sta_list_obj, *bssid_obj, *validity_period_obj, *assoc_control_obj;
    int num = 0;
    em_cmd_t *tmp = NULL;
    em_subdoc_info_t *subdoc;
    em_long_string_t wfa;
    em_cmd_client_assoc_params_t assoc_param;
    // dm_easy_mesh_ctrl_t is not a dm_easy_mesh_t; this constructs one via
    // the dm_network_t converting constructor, not the (deleted) copy ctor
    dm_easy_mesh_t dm = *this;

    subdoc = &evt->u.subdoc;
    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        em_printfout("%s:%d: Failed to parse: %s", __func__, __LINE__, subdoc->buff);
        return EM_PARSE_ERR_GEN;
    }

    snprintf(wfa, sizeof(wfa), "wfa-dataelements:ClientAssocCtrlRequest");

    if ((wfa_obj = cJSON_GetObjectItem(obj, wfa)) == NULL) {
        em_printfout("%s:%d: Failed to get ClientAssocCtrlRequest object", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }

    memset(&assoc_param, 0, sizeof(em_cmd_client_assoc_params_t));

    if ((bssid_obj = cJSON_GetObjectItem(wfa_obj, "BSSID")) == NULL) {
        em_printfout("%s:%d: Failed to get BSSID", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }
    const char *bssid_str = cJSON_GetStringValue(bssid_obj);
    if (bssid_str == NULL) {
        em_printfout("%s:%d: BSSID is not a string", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }
    unsigned int mac[6] = {0};
    int parsed = (strchr(bssid_str, ':') != NULL)
        ? sscanf(bssid_str, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])
        : sscanf(bssid_str, "%02x%02x%02x%02x%02x%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    if (parsed != 6) {
        em_printfout("%s:%d: Invalid BSSID MAC string: %s", __func__, __LINE__, bssid_str);
        cJSON_Delete(obj);
        return 0;
    }
    for (int i = 0; i < 6; i++) {
        assoc_param.bssid[i] = static_cast<unsigned char>(mac[i]);
    }

    if ((assoc_control_obj = cJSON_GetObjectItem(wfa_obj, "AssocControl")) != NULL) {
        if (!cJSON_IsNumber(assoc_control_obj)) {
            em_printfout("%s:%d: AssocControl is not a number", __func__, __LINE__);
            cJSON_Delete(obj);
            return 0;
        }
        double v = cJSON_GetNumberValue(assoc_control_obj);
        if (v != 0.0 && v != 1.0) {
            em_printfout("%s:%d: Invalid AssocControl=%g (allowed: 0=Block, 1=Unblock)", __func__, __LINE__, v);
            cJSON_Delete(obj);
            return 0;
        }
        assoc_param.assoc_control = static_cast<unsigned char>(v);
    }

    if ((validity_period_obj = cJSON_GetObjectItem(wfa_obj, "ValidityPeriod")) != NULL) {
        if (!cJSON_IsNumber(validity_period_obj)) {
            em_printfout("%s:%d: ValidityPeriod is not a number", __func__, __LINE__);
            cJSON_Delete(obj);
            return 0;
        }
        double v = cJSON_GetNumberValue(validity_period_obj);
        const unsigned short vp = static_cast<unsigned short>(v);
        if (v < 0.0 || v > 65535.0 || static_cast<double>(vp) != v) {
            em_printfout("%s:%d: Invalid ValidityPeriod=%g (allowed: integer 0..65535)", __func__, __LINE__, v);
            cJSON_Delete(obj);
            return 0;
        }
        assoc_param.validity_period = vp;
    }

    if ((sta_list_obj = cJSON_GetObjectItem(wfa_obj, "StaMacList")) == NULL) {
        em_printfout("%s:%d: Failed to get StaMacList", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }

    if (!cJSON_IsArray(sta_list_obj)) {
        em_printfout("%s:%d: StaMacList is not an array", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }

    int sta_count = cJSON_GetArraySize(sta_list_obj);
    if (sta_count <= 0) {
        em_printfout("%s:%d: StaMacList cannot be empty", __func__, __LINE__);
        cJSON_Delete(obj);
        return 0;
    }
    if (sta_count > MAX_STA_LIST) {
        em_printfout("%s:%d: StaMacList too large (%d), max allowed=%d", __func__, __LINE__, sta_count, MAX_STA_LIST);
        cJSON_Delete(obj);
        return 0;
    }

    for (int i = 0; i < sta_count; i++) {
        cJSON *sta_obj = cJSON_GetArrayItem(sta_list_obj, i);
        const char *sta_str = cJSON_GetStringValue(sta_obj);
        if (sta_str == NULL) {
            em_printfout("%s:%d: StaMacList contains a non-string entry", __func__, __LINE__);
            cJSON_Delete(obj);
            return 0;
        }
        unsigned int mac[6] = {0};
        int parsed = (strchr(sta_str, ':') != NULL)
            ? sscanf(sta_str, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])
            : sscanf(sta_str, "%02x%02x%02x%02x%02x%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (parsed != 6) {
            em_printfout("%s:%d: Invalid STA MAC string: %s", __func__, __LINE__, sta_str);
            cJSON_Delete(obj);
            return 0;
        }
        for (int k = 0; k < 6; k++) {
            assoc_param.sta_list[i][k] = static_cast<unsigned char>(mac[k]);
        }
    }

    assoc_param.sta_count = static_cast<unsigned char>(sta_count);

    cJSON_Delete(obj);

    pcmd[num] = new em_cmd_client_assoc_ctrl_req_t(assoc_param, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

/* --- runner entry point (keeps the stub classes out of common.h) --- */
int ac_invoke(em_bus_event_t *evt, void **pcmd)
{
    static dm_easy_mesh_ctrl_t ctrl;
    ac_cmd_created = 0;
    memset(&ac_last_params, 0, sizeof(ac_last_params));
    int n = ctrl.analyze_client_assoc(evt, reinterpret_cast<em_cmd_t **>(pcmd));
    for (int i = 0; i < n; i++) { delete static_cast<em_cmd_t *>(pcmd[i]); pcmd[i] = NULL; }  /* free stub cmds (harness only) */
    return n;
}

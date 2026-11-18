/*
 * HANDLER: analyze_remove_device
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::analyze_remove_device. Local arrays: dev_mac_to_keep[32]
 * (one entry per DeviceList item, unbounded), devices_to_delete[32] (one entry per device of the data
 * model that is not kept, unbounded) and the caller's pcmd[EM_MAX_CMD = 16] (one command per device
 * to delete). Real cJSON; dm_easy_mesh_t::string_to_macbytes() (src/dm/dm_easy_mesh.cpp) is copied
 * verbatim (it does strlen(key), so a NULL ID string crashes).
 * Scaffolding: a data model list of ard::ndev devices 02:00:00:00:00:01.. (ard::g_devs); the caller-owned
 * event (ard::evt_buf, runner poisons past the subdoc NUL and the event's guard field) and pcmd array
 * (runner poisons slot 16 onward); em_cmd_remove_device_t only records the device it is given (g_sum).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include "analyze_remove_device.h"

namespace ard {

int g_num = 0;
char g_sum[2048];
int g_cmds = 0;
int g_ndev = 0;
dm_easy_mesh_ctrl_t g_ctrl_obj;
dm_device_t g_devs[ARD_MAXDEV];
dm_easy_mesh_t g_dms[ARD_MAXDEV];

dm_device_t *dm_easy_mesh_list_t::get_first_device() { return g_ndev > 0 ? &g_devs[0] : NULL; }
dm_device_t *dm_easy_mesh_list_t::get_next_device(dm_device_t *dev)
{
    int idx = (int)(dev - g_devs) + 1;
    return idx < g_ndev ? &g_devs[idx] : NULL;
}
dm_easy_mesh_t *dm_easy_mesh_list_t::get_data_model(const char *net_id, const unsigned char *al_mac)
{
    (void)net_id;
    for (int i = 0; i < g_ndev; i++)
        if (memcmp(g_devs[i].m_device_info.intf.mac, al_mac, 6) == 0) return g_dms[i].present ? &g_dms[i] : NULL;
    return NULL;
}
void dm_easy_mesh_t::macbytes_to_string(unsigned char *mac, char *string)
{ snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }

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
int dm_easy_mesh_ctrl_t::analyze_remove_device(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    cJSON *obj, *wfa_obj, *net_obj, *dev_list_obj, *id_obj;
    int i, num = 0;
    em_subdoc_info_t *subdoc;
	mac_address_t dev_mac_to_keep[32];
	int num_devs_to_keep = 0;
	dm_device_t *devices_to_delete[32];
	int num_devs_to_delete = 0;
	char *tmp;
	bool keep = false;
	dm_device_t *device;
	mac_addr_str_t	mac_str;
	dm_easy_mesh_t *dm = NULL;
	em_cmd_t *tmp_cmd;
	em_long_string_t wfa;	

    subdoc = &evt->u.subdoc;
	obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

	snprintf(wfa, sizeof(wfa), "wfa-dataelements:RemoveDevice");

	if ((wfa_obj = cJSON_GetObjectItem(obj, wfa)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	if ((net_obj = cJSON_GetObjectItem(wfa_obj, "Network")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	if ((dev_list_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
		id_obj = cJSON_GetObjectItem(cJSON_GetArrayItem(dev_list_obj, i), "ID");
		tmp = cJSON_GetStringValue(id_obj);
		dm_easy_mesh_t::string_to_macbytes(tmp, dev_mac_to_keep[i]);
	}

	num_devs_to_keep = i;

    cJSON_free(obj);

	device = m_data_model_list.get_first_device();
	while (device != NULL) {
		for (i = 0; i < num_devs_to_keep; i++) {
			if (memcmp(device->m_device_info.intf.mac, dev_mac_to_keep[i], sizeof(mac_address_t)) == 0) {
				keep = true;
				break;
			}
		}

		if (keep == true) {
			keep = false;
		} else {
			devices_to_delete[num_devs_to_delete] = device;
			num_devs_to_delete++;
		}
		device = m_data_model_list.get_next_device(device);
	}

	for (i = 0; i < num_devs_to_delete; i++) {
		device = devices_to_delete[i];
		dm_easy_mesh_t::macbytes_to_string(device->m_device_info.intf.mac, mac_str);
		printf("%s:%d: Device: %s should be deleted\n", __func__, __LINE__, mac_str);	
		dm = m_data_model_list.get_data_model(device->m_device_info.id.net_id, device->m_device_info.intf.mac);
		if (dm != NULL) {
    		pcmd[num] = new em_cmd_remove_device_t(evt->params, *dm);
    		tmp_cmd = pcmd[num];
    		num++;

    		while ((pcmd[num] = tmp_cmd->clone_for_next()) != NULL) {
        		tmp_cmd = pcmd[num];
        		num++;
    		}
		}	
	}

    return num;
}

int invoke(void)
{
    g_sum[0] = '\0';
    g_cmds = 0;
    memset(pcmd_buf, 0, ARD_MAXCMD * sizeof(void *));
    g_num = g_ctrl_obj.analyze_remove_device((em_bus_event_t *)evt_buf, (em_cmd_t **)pcmd_buf);
    for (int i = 0; i < g_num && i < ARD_MAXCMD; i++) delete (em_cmd_t *)pcmd_buf[i];
    return g_num;
}

} /* namespace ard */

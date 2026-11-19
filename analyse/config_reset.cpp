/*
 * HANDLER: dm_easy_mesh_t::encode_config_reset
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_easy_mesh_t::encode_config_reset and macbytes_to_string
 * (src/dm/dm_easy_mesh.cpp). Local arrays: mac_str[18], interface_str[128], preference[8] (string literals). The real cJSON library
 * builds the output; the network / network SSID encoders are stand-ins that write one short string each. The dm_easy_mesh_t object lives
 * on the heap between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_reset.h"

namespace ecr {
box_t *g_box = NULL;

/* --- copied verbatim --- */
char *dm_easy_mesh_t::macbytes_to_string(mac_address_t mac, char* string)
{
    if( mac != NULL) {
        sprintf(const_cast<char *> (string), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0] & 0xff,
            mac[1] & 0xff,
            mac[2] & 0xff,
            mac[3] & 0xff,
            mac[4] & 0xff,
            mac[5] & 0xff);
    }
    return const_cast<char *> (string);
}

int dm_easy_mesh_t::encode_config_reset(em_subdoc_info_t *subdoc, const char *key)
{
    cJSON *parent_obj, *net_obj, *interfaces_obj, *interface_obj, *interface_arr_obj, *ssid_obj, *ssid_arr_objs;
	char *formatted_json;
	mac_addr_str_t	mac_str;
	em_long_string_t	interface_str;
	const char *preference[] = {"First Preference", "Second Preference", "Third Preference", "Fourth Preference", "Fifth Preference", "Sixth Preference", "Seventh Preference", "Eighth Preference"};
	unsigned int i, preference_arraysz = sizeof(preference)/sizeof(*preference);

    if (subdoc == NULL || key == NULL || key[0] == '\0') {
        printf("%s:%d: invalid null or empty argument\n", __func__, __LINE__);
        return -1;
    }

    if ((parent_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create parent object\n", __func__, __LINE__);
        return -1;
    }
	
    if ((net_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(parent_obj, key, net_obj) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	if ((interfaces_obj = cJSON_AddObjectToObject(net_obj, "Interfaces")) == NULL) {
		printf("%s:%d: Could not create interface object\n", __func__, __LINE__);
        return -1;
	}

	if ((interface_arr_obj = cJSON_AddArrayToObject(interfaces_obj, "List")) == NULL) {
        printf("%s:%d: Could not create interface array object\n", __func__, __LINE__);
        return -1;
    }

	for (i = 0; i < m_num_interfaces && i < preference_arraysz; i++) {
		interface_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(interface_arr_obj, interface_obj);
		dm_easy_mesh_t::macbytes_to_string(m_interfaces[i].mac, mac_str);
		snprintf(interface_str, sizeof(em_long_string_t), "%s (%s)", mac_str, m_interfaces[i].name);
		cJSON_AddStringToObject(interface_obj, preference[i], interface_str);
	}

	m_network.encode(net_obj);

    if ((ssid_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create NetworkSSIDList array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(net_obj, "NetworkSSIDList", ssid_arr_objs) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	for (i = 0; i < m_num_net_ssids; i++) {
		if ((ssid_obj = cJSON_CreateObject()) == NULL) {	
        	printf("%s:%d: Could not create ssid object\n", __func__, __LINE__);
        	cJSON_Delete(parent_obj);
        	return -1;
		}
			
		m_network_ssid[i].encode(ssid_obj);
        if (cJSON_AddItemToArray(ssid_arr_objs, ssid_obj) == false) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: Could not create net object\n", __func__, __LINE__);
            return -1;
        }
	}
	
	formatted_json = cJSON_Print(parent_obj);

    //printf("%s:%d: %s\n", __func__, __LINE__, formatted_json);
    snprintf(subdoc->buff, EM_IO_BUFF_SZ, "%s", formatted_json);
    cJSON_free(formatted_json);
    cJSON_Delete(parent_obj);

    return 0;
}

int invoke(const test_case_t *tc)
{
    char *key = NULL; char big[8192];
    if (tc->key) { if (tc->key[0] == '#') { size_t n = (size_t)atoi(tc->key + 1); memset(big, 'k', n); big[n] = 0; key = big; } else key = (char *)tc->key; }
    return g_box->dm.encode_config_reset(tc->null_subdoc ? NULL : &g_box->subdoc, key);
}
} /* namespace ecr */

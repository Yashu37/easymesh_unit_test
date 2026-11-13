/*
 * HANDLER: bstamld_get_inner
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::bstamld_get_inner, with get_table_instance() (same file) and
 * dm_easy_mesh_t::maclist_to_string() (src/dm/dm_easy_mesh.cpp). Local arrays: instance[32],
 * maclist_str[256], maclist[14] (the copy loop is capped at MAX_MACLIST_ITEMS; maclist_to_string() gets the
 * uncapped num_affiliated_bsta), and affiliated_bsta[64].
 * Scaffolding: one device (number 1 / alias 02:00:00:00:00:01) with the bSTA MLD info of bml::test_case_t;
 * raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "bstamld_get_inner.h"

namespace bml {

char g_val[512];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;

class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    bus_error_t raw_data_set(raw_data_t *p, const unsigned char *mac)
    { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return bus_error_success; }
    bus_error_t bstamld_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
void dm_easy_mesh_t::maclist_to_string(mac_address_t mac_list[], size_t mac_count, char *string, uint16_t str_len)
{
    uint8_t idx = 0;

    if (mac_list == NULL) {
        return;
    }

    while (str_len >= sizeof(mac_addr_str_t) && idx < mac_count) {
        dm_easy_mesh_t::macbytes_to_string(mac_list[idx], string);
        string += (sizeof(mac_addr_str_t) - 1);
        str_len -= sizeof(mac_addr_str_t);
        if (++idx >= mac_count || str_len == 0) {
            break;
        }
        *string = ',';
        ++string;
    }
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

    src = strstr(src, ".");
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src += 2;
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src++;
	}

	return src;
}

bus_error_t dm_easy_mesh_ctrl_t::bstamld_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    /* Extract device instance (numeric or alias) and find the dm object for
     * that device instance */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        em_printfout("Device not found");
        return bus_error_invalid_namespace;
    }
    if (!dm->is_bsta_mld_present()) {
        return bus_error_destination_not_found;
    }
    em_bsta_mld_info_t &bsmi = dm->get_bsta_mld_info();

    if (strcmp(param, "MLDMACAddress") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bsmi.mac_addr_valid ? bsmi.mac_addr : ZERO_MAC_ADDR);
    } else if (strcmp(param, "BSSID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, bsmi.ap_mld_mac_addr_valid ? bsmi.ap_mld_mac_addr : ZERO_MAC_ADDR);
    } else if (strcmp(param, "AffiliatedbSTAList") == 0) {
        char maclist_str[MAX_MACLIST_STRLEN] = { 0 };
        mac_address_t maclist[MAX_MACLIST_ITEMS];
        if (bsmi.num_affiliated_bsta) {
            for (unsigned int i = 0; i < bsmi.num_affiliated_bsta && i < MAX_MACLIST_ITEMS; i++) {
                memcpy(maclist[i], bsmi.affiliated_bsta[i].mac_addr, sizeof(mac_address_t));
            }
            dm_easy_mesh_t::maclist_to_string(maclist, bsmi.num_affiliated_bsta, maclist_str, sizeof(maclist_str));
        }
        rc = dm_ctrl->raw_data_set(p_data, maclist_str);
    } else {
        em_printfout("Invalid param: %s", param);
        rc = bus_error_destination_not_found;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.bstamld_get_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace bml */

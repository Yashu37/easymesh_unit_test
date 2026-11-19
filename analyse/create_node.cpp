/*
 * HANDLER: create_node
 *
 * Function copied from unified-wifi-mesh src/em/em_mgr.cpp (develop @ 1ba9529), em_mgr_t::create_node.
 * Local array: mac_str[32] (17 chars + "_al" + NUL fits). The key map is a vector instead of hash_map_t, em_t is a stand-in
 * whose constructor can throw std::runtime_error exactly like the real one for the AL node ("Failed to initialize EC
 * manager"), and whose init() result is configurable. Scaffolding below the handler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_node.h"

namespace cnd {
int g_init_rc = 0; bool g_ctor_throws = false; bool g_name_found = true; int g_ctor_calls = 0, g_init_calls = 0;

int dm_easy_mesh_t::name_from_mac_address(const mac_address_t *mac, char *ifname)
{ (void)mac; if (!g_name_found) return -1; snprintf(ifname, 16, "wlan0"); return 0; }
char *dm_easy_mesh_t::macbytes_to_string(mac_address_t mac, char *string)
{
    if (mac != NULL) {
        sprintf(const_cast<char *>(string), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff, mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
    }
    return string;
}

/* --- copied from src/em/em_mgr.cpp (hash_map calls replaced by the vector map) --- */
em_t *em_mgr_t::create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac,em_profile_type_t profile, em_service_type_t type)
{
    em_t *em = NULL;
    char mac_str[32];

    if (ruid == NULL) {
        printf("%s:%d: Invalid ruid\n", __func__, __LINE__);
        return NULL;
    }

    if (dm_easy_mesh_t::name_from_mac_address(&ruid->mac, ruid->name) != 0) {
        printf("%s:%d: ruid name cannot be determined\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);
	if (is_al_mac) {
		strcat(mac_str, "_al");
	}
	printf("%s:%d key value used:%s\n", __func__, __LINE__, mac_str);
    em = map_get(mac_str);

    if (em != NULL) {
        // update the em
        printf("%s:%d: node with key:%s already exists\n", __func__, __LINE__, mac_str);
        return em;
    }

    em = new em_t(ruid, band, dm, this, profile, type, is_al_mac);
    em->set_is_dpp_onboarding(is_agent_dpp_onboarding());
    if (em->init() != 0) {
        delete em;

        return NULL;
    }

    // add this em to hash map
	pthread_mutex_lock(&m_mutex);
    m_map.push_back({strdup(mac_str), em});
	pthread_mutex_unlock(&m_mutex);
    printf("%s:%d: created entry for key:%s\n", __func__, __LINE__, mac_str);

    return em;
}

em_mgr_t *g_mgr = NULL; em_t *g_ret = NULL; em_interface_t *g_ruid = NULL;
void invoke(const test_case_t *tc)
{
    g_ret = g_mgr->create_node(tc->null_ruid ? NULL : g_ruid, 1, NULL, tc->is_al, 3, 1);
}
} /* namespace cnd */

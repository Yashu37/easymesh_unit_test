/*
 * HANDLER: create_data_model
 *
 * Function copied from unified-wifi-mesh src/dm/dm_easy_mesh_list.cpp (develop @ 1ba9529),
 * dm_easy_mesh_list_t::create_data_model, with get_network() and get_data_model() (same file). Local arrays: mac_str[18],
 * key (em_short_string_t = 64 bytes, filled with snprintf "%s@%s"), em_policy[8], op_class[6], policy[8]. Only the three
 * constant initialiser tables (em_policy / op_class) are shortened to the same element counts with stand-in types; the code
 * of the function is unchanged. Scaffolding: dm_easy_mesh_t / dm_device_t / dm_network_t stand-ins (init, set_policy,
 * set_channels_list, ... only record), the list is a vector, assert() is the real one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_data_model.h"

namespace cdm {
bool g_name_found = false;
dm_easy_mesh_list_t *g_list = NULL; dm_easy_mesh_t *g_ret = NULL; std::vector<dm_easy_mesh_t *> g_dms;

void dm_easy_mesh_t::init() { memset((void *)this, 0, sizeof(*this)); on_dm_created(this); }
void *hash_map_get_first(hash_map_t *m) { return m->v.empty() ? NULL : m->v[0].second; }
void *hash_map_get_next(hash_map_t *m, void *cur)
{ for (size_t i = 0; i < m->v.size(); i++) if (m->v[i].second == cur) return i + 1 < m->v.size() ? m->v[i + 1].second : NULL; return NULL; }
void *hash_map_get(hash_map_t *m, const char *key) { for (auto &e : m->v) if (!strcmp(e.first, key)) return e.second; return NULL; }
void hash_map_put(hash_map_t *m, char *key, void *val) { m->v.push_back({key, val}); }

/* --- copied from src/dm/dm_easy_mesh_list.cpp --- */
dm_network_t *dm_easy_mesh_list_t::get_network(const char *key)
{
    dm_network_t *net = NULL;
    dm_easy_mesh_t *dm = NULL;
    bool found = false;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        net = dm->get_network();
		if (strncmp(net->m_net_info.id, key, strlen(key)) == 0) {
	    	found = true;
	    	break;
		}
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    return (found == true) ? net:NULL;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::get_data_model(const char *net_id, const unsigned char *al_mac)
{
    dm_easy_mesh_t *dm = NULL;
    mac_addr_str_t mac_str;
    em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (al_mac), mac_str);
    snprintf(key, sizeof(key), "%s@%s", net_id, mac_str);
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get(m_list, key));

    return dm;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile, bool controller)
{
    dm_easy_mesh_t *dm = NULL, *ref_dm, *ctrl_dm;
    mac_addr_str_t mac_str;
    em_short_string_t	key;
    dm_network_t *net, *pnet;
    dm_device_t *dev;
    dm_network_ssid_t *net_ssid, *pnet_ssid;
	// Per-radio policies (radio_metrics_rep, steering_param) are NOT initialized here.
	// They are created with real radio MACs in put_radio() when radios are discovered.
	const em_policy_t	em_policy[] = { {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8} };   /* harness: same count (8) as the original table */
    unsigned int i;
    bool colocated = false;
	dm_op_class_t	op_class[EM_MAX_PRE_SET_CHANNELS] 	= 	{ dm_op_class_t(83), dm_op_class_t(128), dm_op_class_t(135), dm_op_class_t(81), dm_op_class_t(115), dm_op_class_t(131) };   /* harness: same count (6) */
	dm_policy_t	policy[] = {
								dm_policy_t(em_policy[0]), dm_policy_t(em_policy[1]),
								dm_policy_t(em_policy[2]), dm_policy_t(em_policy[3]),
								dm_policy_t(em_policy[4]), dm_policy_t(em_policy[5]),
								dm_policy_t(em_policy[6]), dm_policy_t(em_policy[7])
							};

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (al_intf->mac), mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);


    dm = new dm_easy_mesh_t();
    dm->init();

    if (controller == true) {
        em_printfout("Creating data model as controller ...");
        dm->set_controller(controller);
    } else {
        em_printfout("Creating data model as agent...");
        //Identify colocated and set colocated here
        em_interface_name_t name;
        if (dm_easy_mesh_t::name_from_mac_address(&al_intf->mac, name) == 0) {
            em_printfout("MAC %s address exists on this device. DM is colocated.", mac_str);
            colocated = true;
            dm->set_colocated(colocated);

            if ((net = get_network(net_id)) != NULL) {
                ctrl_dm = get_data_model(GLOBAL_NET_ID, net->m_net_info.ctrl_id.mac);
                assert(ctrl_dm != NULL);
                pnet = ctrl_dm->get_network();
                *pnet = *net;
                //if colocated, set the agent interface mac address in controller's dm
                ctrl_dm->m_network.set_colocated_agent_interface_mac(const_cast<unsigned char *>(al_intf->mac));
                em_printfout("Set colocated agent interface mac %s in controller dm",
                    util::mac_to_string(ctrl_dm->m_network.get_colocated_agent_interface_mac()).c_str());
                //also trigger db update of networklist for colocated agent id
                ctrl_dm->set_db_cfg_param(db_cfg_type_network_list_update, "");
            }
        }
    }
    em_printfout("Created data model for net_id: %s mac: %s, is_colocated:%d is_controller:%d", net_id, mac_str, colocated, controller);

    dev = dm->get_device();
    memcpy(dev->m_device_info.intf.mac, al_intf->mac, sizeof(mac_address_t));
    strncpy(dev->m_device_info.id.net_id, net_id, strlen(net_id) + 1);
	if (controller == true) {
		memcpy(dev->m_device_info.id.dev_mac, al_intf->mac, sizeof(mac_address_t));
		dev->m_device_info.id.media = dm->m_network.m_net_info.media;
		//TODO: Monitor Checks
		//memcpy(dev->m_device_info.backhaul_mac.mac, al_intf->mac, sizeof(mac_address_t));
		dev->m_device_info.backhaul_mac.media = dm->m_network.m_net_info.media;
		em_printfout("Backhaul mac updated to :%s device media:%d backhaul media:%d",
			util::mac_to_string(dev->m_device_info.backhaul_mac.mac).c_str(),
			dev->m_device_info.id.media, dev->m_device_info.backhaul_mac.media);
		//Update the easymesh configuration file to specify colocated agent as true.
		dev->update_easymesh_json_cfg(true);
	} else {
        dm->set_id();
        em_printfout("dm->get_id():%d", dm->get_id());
    }
    dev->m_device_info.profile = profile;
	dm->set_channels_list(op_class, EM_MAX_PRE_SET_CHANNELS);
	
	for (i = 0; i < sizeof(em_policy)/sizeof(em_policy_t); i++) {
		dm->set_policy(policy[i]);
	}

	em_printfout("Number of policies: %d", dm->get_num_policy());

    // is this the first data model
    if ((net = get_network(net_id)) != NULL) {
        pnet = dm->get_network();
        *pnet = *net;

        ref_dm = get_data_model(net->m_net_info.id, net->m_net_info.ctrl_id.mac);
        if(ref_dm != NULL) {
            dm->set_num_network_ssid(ref_dm->get_num_network_ssid());
            //printf("%s:%d: Number of network ssid in reference data model: %d\n", __func__, __LINE__, ref_dm->get_num_network_ssid());
            for (i = 0; i < ref_dm->get_num_network_ssid(); i++) {
                pnet_ssid = dm->get_network_ssid(i);
                net_ssid = ref_dm->get_network_ssid(i);
                *pnet_ssid = *net_ssid;
            }
        } else {
            em_printfout("Reference data model not found for network: %s and ctrl AL mac: %s",
                net->m_net_info.id, util::mac_to_string(net->m_net_info.ctrl_id.mac).c_str());
        }
    }
    em_printfout("Putting data model at key: %s", key);
    hash_map_put(m_list, strdup(key), dm);

    return dm;
}

void invoke(const test_case_t *tc)
{
    const char *net = (tc->net_id || tc->long_len > 0) ? name_store + CDM_LEFT : NULL;
    g_ret = g_list->create_data_model(net, tc->al_null ? NULL : g_al, 3, tc->controller);
}
} /* namespace cdm */

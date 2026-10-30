#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "common.h"

#ifndef MACSTRFMT
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
#endif

/* Handlers called by handle_topology_response() that the topology response tests do not exercise */
void em_configuration_t::handle_ap_vendor_operational_bss(unsigned char *value, unsigned int len)
{
}

int em_configuration_t::handle_bss_configuration_report(unsigned char *buff, unsigned int len)
{
	return 0;
}

int em_configuration_t::handle_bsta_radio_cap(unsigned char *buff, unsigned int len)
{
	return 0;
}

int em_configuration_t::handle_ap_mld_config_tlv(unsigned char *buff, unsigned int len)
{
	return 0;
}

int em_configuration_t::handle_assoc_sta_mld_conf_rep_tlv(unsigned char *buff, unsigned int len)
{
	return 0;
}

static bool handle_assoc_sta_mld_topology_update(dm_easy_mesh_t *dm)
{
	return false;
}

/* Copied from unified-wifi-mesh src/em/em_msg.cpp (PR 822, 9b04018) */
bool em_msg_t::parse_profile_tlv(const unsigned char *value, uint16_t value_len, em_profile_type_t *profile)
{
    if ((value == nullptr) || (profile == nullptr)) {
        em_printfout("Error: Invalid Profile TLV input: value=%p profile=%p", static_cast<const void *>(value), static_cast<void *>(profile));
        return false;
    }

    // Multi-AP Profile TLV may be encoded as 1 byte (legacy) or 4 bytes (profile + 3 reserved bytes).
    if ((value_len != sizeof(unsigned char)) && (value_len != 4U)) {
        em_printfout("Error: Invalid Profile TLV length %u", static_cast<unsigned int>(value_len));
        return false;
    }

    const unsigned char raw_profile = value[0];
    if (raw_profile >= static_cast<unsigned char>(em_profile_type_max)) {
        em_printfout("Error: Invalid Profile TLV value %u", static_cast<unsigned int>(raw_profile));
        return false;
    }

    *profile = static_cast<em_profile_type_t>(raw_profile);
    return true;
}

/* Copied from unified-wifi-mesh src/em/config/em_configuration.cpp (PR 822, 9b04018) */
dm_easy_mesh_t *em_configuration_t::get_peer_dm(const mac_address_t al_mac)
{
    em_mgr_t *mgr = get_mgr();
    dm_easy_mesh_t *dm = (mgr != nullptr) ? mgr->get_data_model(GLOBAL_NET_ID, al_mac) : nullptr;
    // The controller's own model must not hold a peer's profile; the peer model is created later by dm commit.
    return (dm != nullptr || get_service_type() == em_service_type_ctrl) ? dm : get_data_model();
}

em_profile_type_t em_configuration_t::get_peer_profile(const mac_address_t al_mac)
{
    dm_easy_mesh_t *dm = get_peer_dm(al_mac);
    em_profile_type_t profile = (dm != nullptr) ? dm->get_device()->get_peer_profile() : em_profile_type_reserved;
    return (profile == em_profile_type_reserved) ? em_profile_type_1 : profile;
}

void em_configuration_t::set_peer_profile(const mac_address_t al_mac, em_profile_type_t profile)
{
    if (dm_easy_mesh_t *dm = get_peer_dm(al_mac)) {
        dm->get_device()->set_peer_profile(profile);
    }
}

int em_configuration_t::handle_topology_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    unsigned int tmp_len;
    int ret = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool found_op_bss = false;
    bool found_profile = false;
    bool found_bss_config_rprt = false;
    bool found_ap_mld = false;
    unsigned int assoc_sta_mld_count = 0;
    em_profile_type_t profile = em_profile_type_reserved;
	dm_easy_mesh_t *dm;
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    uint8_t *src_al_mac = hdr->src;
    
	dm = get_data_model();

    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while (true) {
        if (tmp_len < sizeof(em_tlv_t)) {
            em_printfout("Incomplete TLV header: remaining=%u\n", tmp_len);
	    return -1;
	}
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        unsigned int tlv_len = ntohs(tlv->len);

        if (tlv_len > tmp_len - sizeof(em_tlv_t)) {
            em_printfout("Invalid TLV length=%u, remaining=%u\n", tlv_len, tmp_len - sizeof(em_tlv_t));
            return -1;
        }
        if (tlv->type != em_tlv_type_profile) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + tlv_len);

            continue;
        } else {
            // Validate length and value before assigning profile to avoid invalid enum data.
            if (em_msg_t::parse_profile_tlv(tlv->value, ntohs(tlv->len), &profile)) {
                found_profile = true;
            } else {
                em_printfout("Error: Invalid Profile TLV in topology response");
            }
            tmp_len -= static_cast<unsigned int>(sizeof(em_tlv_t) + tlv_len);
            tlv = reinterpret_cast<em_tlv_t *>(
                  reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + tlv_len);
            continue;
        }
    }

    // For backward compatibility with earlier EasyMesh specifications.
    if (found_profile == true && profile != em_profile_type_reserved) {
        set_peer_profile(src_al_mac, profile);
        em_printfout("Topology response received from %s with profile: %d", util::mac_to_string(src_al_mac).c_str(), profile);
    } else {
        // MultiAP profile TLV is mandatory for profile >= em_profile_type_2.
        // FALL back to profile 1 for backward compatibility with earlier EasyMesh specifications.
        set_peer_profile(src_al_mac, em_profile_type_1);
        em_printfout("Topology response received from %s with no profile TLV, assuming profile: %d", util::mac_to_string(src_al_mac).c_str(), em_profile_type_1);
    }
    if (em_msg_t(em_msg_type_topo_resp, get_peer_profile(src_al_mac), buff, len).validate(errors) == 0) {
        em_printfout("topology response msg validation failed, ignoring message");
        return -1;
    }
        
    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

	while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
		if (tlv->type != em_tlv_type_vendor_operational_bss) {
			tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
			tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
			continue;
		} else {
			handle_ap_vendor_operational_bss(tlv->value, tlv->len);
			break;
		}
	}
	tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
	tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    while (tmp_len >= sizeof(em_tlv_t)) {
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        unsigned int tlv_len = ntohs(tlv->len);

        if (tlv_len > tmp_len - sizeof(em_tlv_t)) {
            em_printfout("Invalid TLV length=%u, remaining=%u\n", tlv_len, tmp_len - sizeof(em_tlv_t));
            return -1;
        }
        if (tlv->type != em_tlv_type_operational_bss) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + tlv_len);

            continue;

        } else {
            found_op_bss = true;
            break;
        }
    }

    if (found_op_bss == false) {
        em_printfout("Could not find operational bss, failing message");
        return -1;
    }


        int rc = handle_ap_operational_bss(tlv->value, ntohs(tlv->len));
        if (rc != 0) {
            if (rc == -2) {
                em_printfout("Failed to handle operational BSS due to SSID misconfiguration.");
                static_cast<em_t*>(this)->set_ssid_mismatch(true);
            } else {
                em_printfout("Operational BSS handling failed rc=%d", rc);
            }
            return rc;
        }


    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_bss_conf_rep) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast <em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_bss_config_rprt = true;
            break;
        }
    }

    if (found_bss_config_rprt) {
        if (handle_bss_configuration_report(tlv->value, tlv->len) != 0) {
            em_printfout("BSS Configuration Report handling failed");
            return -1;
        }
    } else {
        // bss_conf_rep is optional; reset cursor so subsequent TLV searches still run
        tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        tmp_len = len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    }

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_bh_sta_radio_cap) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast <em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
            continue;
        } else {
            handle_bsta_radio_cap(tlv->value, tlv->len);
            break;
        }
    }

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_ap_mld_config) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_ap_mld = true;
            break;
       }
    }

    if (found_ap_mld == true) {
        em_printfout("Found AP MLD details in topology response message");
        handle_ap_mld_config_tlv(tlv->value, ntohs(tlv->len));
    }
    em_printfout("No of AP MLDs: %d", dm->m_num_ap_mld);

    // Parse Associated STA MLD Configuration Report TLVs.
    tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    assoc_sta_mld_count = 0;
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_mld_conf_rep) {
            em_printfout("Found Assoc STA MLD Configuration Report TLV #%u", assoc_sta_mld_count);
            handle_assoc_sta_mld_conf_rep_tlv(tlv->value, htons(tlv->len));
            assoc_sta_mld_count++;
        }
        tmp_len -= static_cast<unsigned int>(sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }
    em_printfout("Total Assoc STA MLD TLVs parsed: %u, m_num_assoc_sta_mld=%u",
        assoc_sta_mld_count, dm->m_num_assoc_sta_mld);

    if (handle_assoc_sta_mld_topology_update(dm) == true) {
        dm->set_db_cfg_param(db_cfg_type_sta_list_update, "");
    }

    em_printfout("Src al mac: " MACSTRFMT, MAC2STR(src_al_mac));

    if (dm->get_colocated() == true) {
        memset(dm->m_device.m_device_info.backhaul_alid.mac, 0, sizeof(mac_address_t));
    } else {
        //backhaul_alid is the alid of the Agent on the network that is providing the backhaul for this EasyMesh Agent.
        //This would be the colocated AL interface mac for extenders connected in star topology.
        //For daisy chain topology, this would be the AL interface mac of the agent that is providing backhaul connectivity.
        // Obtain the mesh_sta information of this dm.
	    em_bss_info_t *bss = dm->get_bsta_bss_info();
        dm_device_t *backhaul_dev = NULL;
        if (bss != NULL) {
            //TODO: Get backhaul_dev matching bss->id.bssid and al_mac not matching src_al_mac
            //from the list of dm.
            /*
            backhaul_dev = em_mgr()->get_dm_dev(src_al_mac, bss->id.bssid);
            dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();
            if (dm_ctrl) {
                backhaul_dev = dm_ctrl->get_dm_dev(src_al_mac, bss->id.bssid);
            }*/
        } else {
            em_printfout("Backhaul STA not found in any bss for this device:%s",
                util::mac_to_string(src_al_mac).c_str());
        }
        if (backhaul_dev != NULL) {
            em_device_info_t *bhdi = backhaul_dev->get_device_info();
            memcpy(dm->m_device.m_device_info.backhaul_alid.mac, bhdi->id.dev_mac, sizeof(mac_address_t));
            em_printfout("Backhaul ALID mac address:%s updated from agent dm: %s",
                    util::mac_to_string(bhdi->id.dev_mac).c_str(), util::mac_to_string(src_al_mac).c_str());
        } else {
            memset(dm->m_device.m_device_info.backhaul_alid.mac, 0, sizeof(mac_address_t));
        }
    }

    em_printfout("updated dm dev_info's colocated: %d backhaul_mac: %s and backhaul_alid: %s", dm->get_colocated(),
        util::mac_to_string(dm->m_device.m_device_info.backhaul_mac.mac).c_str(),
        util::mac_to_string(dm->m_device.m_device_info.backhaul_alid.mac).c_str());

	return ret;
}

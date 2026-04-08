#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>


std::pair<FILE*, std::string> get_module_log_fd_name(int module, int level){
        return std::make_pair(stdout, "log");
}

void get_formatted_time_em(char *time_buff){
        strcpy(time_buff, "00:00:00");
}

em_capability_t::em_capability_t()
{
}

em_capability_t:: ~em_capability_t()
{
}

bool em_sm_t::validate_sm(em_state_t state)
{
        return true;
}

int em_sm_t::set_state(em_state_t state)
{
        if (validate_sm(state) == true) {
                m_state = state;
                return 0;
        }

        return -1;
}

dm_bss_t::dm_bss_t(em_bss_info_t *bss)
{
    memcpy(&m_bss_info, bss, sizeof(em_bss_info_t));
}

dm_bss_t::dm_bss_t(const dm_bss_t& bss)
{
        memcpy(&m_bss_info, &bss.m_bss_info, sizeof(em_bss_info_t));
}

dm_bss_t::dm_bss_t()
{

}

dm_bss_t::~dm_bss_t()
{

}

unsigned int em_msg_t::validate(char *errors[])
{
    em_tlv_t *tlv;
    unsigned int i, len;
    bool validation = true;

    for (i = 0; i < m_num_tlv; i++) {
        tlv =  reinterpret_cast<em_tlv_t *> (m_buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        len = m_len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

        while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
            if (tlv->type == m_tlv_member[i].m_type) {
                m_tlv_member[i].m_present = true;
                break;
            }
            len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> ((reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + htons(tlv->len)));
        }

        if ((m_tlv_member[i].m_requirement == mandatory) &&((m_tlv_member[i].m_present == false)||((sizeof(em_tlv_t) + htons(tlv->len)) < static_cast<size_t> (m_tlv_member[i].m_tlv_length)))) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            validation = false;
            if (m_tlv_member[i].m_present == false) {
                //printf("%s:%d; TLV not present\n", __func__, __LINE__);
            }

            if (((sizeof(em_tlv_t) + htons(tlv->len)) < static_cast<size_t> (m_tlv_member[i].m_tlv_length))) {
                //printf("%s:%d; TLV type: 0x%04x Length: %d, length validation error\n", __func__, __LINE__, tlv->type, htons(tlv->len));
            }
        }

        if ((m_tlv_member[i].m_requirement == bad) && (m_tlv_member[i].m_present == true)) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            //printf("%s:%d; TLV type: 0x%04x Length: %d, presence validation error, profile: %d\n", __func__, __LINE__,
            //tlv->type, htons(tlv->len), m_profile);
            validation = false;
        }
    }

    if (validation == false) {
        for (i = 0; i < EM_MAX_TLV_MEMBERS; i++) {
            if (errors[i] != NULL) {
                printf("Failed TLV [%d]: %s\n",(i+1),errors[i]);
            }
        }
    }

    return validation;
}

void em_msg_t::autoconfig_search()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_searched_role, mandatory, "table 6-22 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_autoconf_freq_band, mandatory, "table 6-23 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_searched_service, optional, "17.2.2 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
}

void em_msg_t::autoconfig_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_role, mandatory, "table 6-24 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_freq_band, mandatory, "table 6-25 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_layer_security_cap, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.67 of Wi-Fi Easy Mesh 5.0", 6);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ctrl_cap, optional, "17.2.94 of Wi-Fi Easy Mesh 5.0", 3);

}
void em_msg_t::autoconfig_wsc_m1() //M1 from MAP Agent
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_wsc, mandatory, "table 8 of WSC v2.0.7", 264);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.48 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.52 of Wi-Fi Easy Mesh 5.0", 2);


}

void em_msg_t::autoconfig_wsc_m2() //M2 from MAP Controller
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_id, mandatory, "17.2.3 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_wsc, mandatory, "table 9 of WSC v2.0.7", 264);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, (m_profile > em_profile_type_1) ? optional:bad, "17.2.49 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.50 of Wi-Fi Easy Mesh 5.0", 2);

}

void em_msg_t::topo_disc()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_mac_address, mandatory, "table 6-9 of IEEE-1905-1", 9);

}

void em_msg_t::topo_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_assoc_event, optional, "17.2.20 of Wi-Fi Easy Mesh 5.0", 15);

}


void em_msg_t::topo_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);

}

void em_msg_t::topo_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_info, mandatory, "table 6-10 of IEEE-1905-1", 19);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_operational_bss, mandatory, "17.2.4 of Wi-Fi Easy Mesh 5.0", 18);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_associated_clients, optional, "17.2.5 of Wi-Fi Easy Mesh 5.0", 20);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rep, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.75 of Wi-Fi Easy Mesh 5.0", 17);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, optional, "17.2.96 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bsta_mld_config, optional, "17.2.97 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_mld_conf_rep, optional, "17.2.98 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tid_to_link_map_policy, optional, "17.2.97 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_bridging_cap, optional, "table 6-11 of IEEE-1905-1", 11);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_non1905_neigh_list, optional, "table 6-14 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_neigh_list, optional, "table 6-15 of IEEE-1905-1", 15);
}


void em_msg_t::topo_vendor()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_vendor_specific, mandatory, "table 6-7 of IEEE-1905-1", 6);
}

void em_msg_t::link_metric_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_link_metric, mandatory, "table 6-16 of IEEE-1905-1", 11);

}

void em_msg_t::link_metric_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, optional, "table 6-17 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, optional, "table 6-19 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_link_metric_result_code, optional, "table 6-21 of IEEE-1905-1", 4);
}

void em_msg_t::autoconfig_renew()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_role, mandatory, "table 6-24 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_freq_band, mandatory, "table 6-25 of IEEE-1905-1", 4);
}
void em_msg_t::ap_cap_query()
{
    //No TLVs are required in this message
}

void em_msg_t::ap_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_cap, mandatory, "17.2.6 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ht_cap, optional, "17.2.8 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_vht_cap, optional, "17.2.9 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_he_cap, optional, "17.2.10 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_wifi6_cap, (m_profile > em_profile_type_2) ? optional:bad, "17.2.72 of Wi-Fi Easy Mesh 5.0", 24);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.38 of Wi-Fi Easy Mesh 5.0", 17);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_layer_security_cap, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.67 of Wi-Fi Easy Mesh 5.0", 6);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.46 of Wi-Fi Easy Mesh 5.0", 21);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.48 of Wi-Fi Easy Mesh 5.0", 6);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_metric_cltn_interval, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.59 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_inventory, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.76 of Wi-Fi Easy Mesh 5.0", 270);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, optional, "17.2.52 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::policy_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_policy, optional, "17.2.11 of Wi-Fi Easy Mesh 5.0", 27);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_metric_reporting_policy, optional, "17.2.12 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, (m_profile > em_profile_type_1) ? optional:bad, "17.2.49 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.50 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_rprt_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.37 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unsucc_assoc_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.58 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_backhaul_bss_conf, (m_profile > em_profile_type_1) ? optional:bad, "17.2.66 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_policy, optional, "17.2.92 of Wi-Fi Easy Mesh 5.0", 37);
}

void em_msg_t::channel_pref_query()
{
    //No TLVs are required in this message
}

void em_msg_t::channel_pref_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_pref, optional, "17.2.13 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_op_restriction, optional, "17.2.14 of Wi-Fi Easy Mesh 5.0", 14);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_cmpltn_rprt, (m_profile > em_profile_type_1) ? optional:bad, "17.2.44 of Wi-Fi Easy Mesh 5.0", 16);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_sts_rprt, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.45 of Wi-Fi Easy Mesh 5.0", 19);
}

void em_msg_t::channel_sel_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_pref, optional, "17.2.13 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tx_power, optional, "17.2.15 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_req, optional, "17.2.89 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::channel_sel_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_sel_resp, mandatory, "17.2.16 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_cfg_rsp, optional, "17.2.91 of Wi-Fi Easy Mesh 5.0", 10);
}
void em_msg_t::op_channel_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_op_channel_report, mandatory, "17.2.17 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_rep, optional, "17.2.90 of Wi-Fi Easy Mesh 5.0", 38);
}
void em_msg_t::client_cap_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_info, mandatory, "17.2.18 of Wi-Fi Easy Mesh 5.0", 15);
}


void em_msg_t::client_steering_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_request, (m_profile > em_profile_type_1) ? optional:bad, "17.2.29 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile2_steering_request, (m_profile > em_profile_type_1) ? optional:bad, "17.2.57 of Wi-Fi Easy Mesh 5.0", 15);

}


void em_msg_t::client_steering_btm_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_btm_rprt, mandatory, "17.2.30 of Wi-Fi Easy Mesh 5.0", 16);
}


void em_msg_t::client_assoc_ctrl_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_assoc_ctrl_req, mandatory, "17.2.31 of Wi-Fi Easy Mesh 5.0", 19);
}


void em_msg_t::steering_complete()
{
    // No TLVs are required in this message.
}

void em_msg_t::higher_layer_data()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_higher_layer_data, mandatory, "17.2.34 of Wi-Fi Easy Mesh 5.0", 4);
}

void em_msg_t::bh_steering_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_steering_req, mandatory, "17.2.32 of Wi-Fi Easy Mesh 5.0", 17);
}

void em_msg_t::bh_steering_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_steering_rsp, optional, "17.2.33 of Wi-Fi Easy Mesh 5.0", 15);
}

void em_msg_t::client_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_info, mandatory, "17.2.18 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_cap_report, mandatory, "17.2.19 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
}

void em_msg_t::ap_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics_query, mandatory, "17.2.21 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_id, (m_profile > em_profile_type_1) ? optional:bad, "17.2.3 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::ap_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics, mandatory, "17.2.22 of Wi-Fi Easy Mesh 5.0", 16);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_ext_metric, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.61 of Wi-Fi Easy Mesh 5.0", 33);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_metric, (m_profile > em_profile_type_1) ? optional:bad, "17.2.60 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_traffic_sts, optional, "17.2.35 of Wi-Fi Easy Mesh 5.0", 37);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_link_metric, optional, "17.2.24 of Wi-Fi Easy Mesh 5.0", 29);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_ext_link_metric, (m_profile > em_profile_type_1) ? optional:bad, "17.2.62 of Wi-Fi Easy Mesh 5.0", 32);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_wifi6_sta_rprt, (m_profile > em_profile_type_2) ? optional:bad, "17.2.73 of Wi-Fi Easy Mesh 5.0", 12);
}

void em_msg_t::sta_link_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::sta_link_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_link_metric, mandatory, "17.2.24 of Wi-Fi Easy Mesh 5.0", 29);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_ext_link_metric, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.62 of Wi-Fi Easy Mesh 5.0", 32);
}

void em_msg_t::unassoc_sta_link_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unassoc_sta_link_metric_query, mandatory, "17.2.25 of Wi-Fi Easy Mesh 5.0", 13);
}
void em_msg_t::unassoc_sta_link_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unassoc_sta_link_metric_rsp, mandatory, "17.2.26 of Wi-Fi Easy Mesh 5.0", 11);
}

void em_msg_t::beacon_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bcon_metric_query, mandatory, "17.2.27 of Wi-Fi Easy Mesh 5.0", 23);

}
void em_msg_t::beacon_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bcon_metric_rsp, mandatory, "17.2.28 of Wi-Fi Easy Mesh 5.0", 11);
}


void em_msg_t::combined_infra_metrics()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics, mandatory, "17.2.22 of Wi-Fi Easy Mesh 5.0", 24);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, mandatory, "section 6.4.11 of IEEE-1905-1", 50);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, mandatory, "section 6.4.11 of IEEE-1905-1", 50);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, mandatory, "section 6.4.12 of IEEE-1905-1", 38);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, mandatory, "section 6.4.12 of IEEE-1905-1", 38);
}

void em_msg_t::channel_scan_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_req, mandatory, "17.2.39 of Wi-Fi Easy Mesh 5.0", 13);

}

void em_msg_t::qos_mgmt_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_desc, mandatory, "17.2.93 of Wi-Fi Easy Mesh 5.0", 17);
}

void em_msg_t::anticipated_channel_usage_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_usage, mandatory, "17.2.88 of Wi-Fi Easy Mesh 5.0", 41);
}

void em_msg_t::anticipated_channel_pref()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_anticipated_channel_pref, mandatory, "17.2.87 of Wi-Fi Easy Mesh 5.0", 8);
}


void em_msg_t::agent_list()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_agent_list, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.77 of Wi-Fi Easy Mesh 5.0", 12);
}

void em_msg_t::failed_conn()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bssid, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.74 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_status_code, mandatory, "17.2.63 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_reason_code, optional, "17.2.64 of Wi-Fi Easy Mesh 5.0", 5);
}

void em_msg_t::dpp_bootstrap_uri_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_bootstrap_uri_notification, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.81 of Wi-Fi Easy Mesh 5.0", 21);
}

void em_msg_t::i1905_encap_eapol()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_encap_eapol, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.80 of Wi-Fi Easy Mesh 5.0", 3);
}

void em_msg_t::chirp_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
}


void em_msg_t::bss_config_res()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rep, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.75 of Wi-Fi Easy Mesh 5.0", 17);
}


void em_msg_t::bss_config_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rsp, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.85 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, optional, "17.2.49 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, optional, "17.2.50 of Wi-Fi Easy Mesh 5.0", 7);
}


void em_msg_t::bss_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, mandatory, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, mandatory, "17.2.48 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, mandatory, "17.2.52 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_req, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.84 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_akm_suite, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.78 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_sta_radio_cap, optional, "17.2.65 of Wi-Fi Easy Mesh 5.0", 15);
}

void em_msg_t::channel_scan_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_timestamp, mandatory, "17.2.41 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_rslt, mandatory, "17.2.40 of Wi-Fi Easy Mesh 5.0", 32);
}
void em_msg_t::dpp_cce_ind()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t( em_tlv_type_dpp_cce_indication, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.82 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::i1905_rekey_req()
{
    //No TLVs are required in this message.

}
void em_msg_t::i1905_decrypt_fail()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, (m_profile > em_profile_type_2) ? mandatory:bad, "table 6.4.3 of IEEE 1905.1", 9);
}
void em_msg_t::cac_term()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_term, mandatory, "17.2.43 of Wi-Fi Easy Mesh 5.0", 4);// actual 12
}
void em_msg_t::client_disassoc_stats()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_reason_code, mandatory, "17.2.64 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_traffic_sts, mandatory, "17.2.35 of Wi-Fi Easy Mesh 5.0", 37);
}
void em_msg_t::svc_prio_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_svc_prio_rule, (m_profile > em_profile_type_2) ? optional:bad, "17.2.70 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dscp_map_tbl, (m_profile > em_profile_type_2) ? optional:bad, "17.2.71 of Wi-Fi Easy Mesh 5.0", 67);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_desc, optional, "17.2.93 of Wi-Fi Easy Mesh 5.0", 17);
}
void em_msg_t::err_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_error_code, mandatory, "17.2.51 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::assoc_status_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sts_notif, mandatory, "17.2.53 of Wi-Fi Easy Mesh 5.0", 11);
}
void em_msg_t::tunneled()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_src_info, mandatory, "17.2.54 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tunneled_msg_type, mandatory, "17.2.55 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tunneled, mandatory, "17.2.56 of Wi-Fi Easy Mesh 5.0", 3);
}
void em_msg_t::bh_sta_cap_query()
{
    //No TLVs are required in this message
}
void em_msg_t::bh_sta_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_sta_radio_cap, optional, "17.2.65 of Wi-Fi Easy Mesh 5.0", 15);
}
void em_msg_t::proxied_encap_dpp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_encap_dpp, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.79 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::direct_encap_dpp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_msg, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.86 of Wi-Fi Easy Mesh 5.0", 3);
}
void em_msg_t::reconfig_trigger()
{
    //No TLVs are required in this message
}

void em_msg_t::cac_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_req, mandatory, "17.2.42 of Wi-Fi Easy Mesh 5.0", 12);
}

void em_msg_t::ap_mld_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, mandatory, "17.2.96 of Wi-Fi Easy Mesh 6.0", 4);
}

void em_msg_t::ap_mld_config_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, mandatory, "17.2.96 of Wi-Fi Easy Mesh 6.0", 4);
}

void em_msg_t::i1905_ack()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
}

em_msg_t::em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len)
{
    m_type = type;
    m_profile = profile;
    m_num_tlv = 0;
    m_buff  = tlvs;
    m_len = len;
    m_num_errors = 0;

    switch (type) {
        case em_msg_type_autoconf_search:
            autoconfig_search();
            break;
        case em_msg_type_autoconf_resp:
            autoconfig_resp();
            break;

        case em_msg_type_autoconf_wsc:
            tlvs = tlvs + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
            len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));
            if(em_configuration_t::get_wsc_msg_type(tlvs,len) == em_wsc_msg_type_m1) {
                autoconfig_wsc_m1();
            } else if (em_configuration_t::get_wsc_msg_type(tlvs, len) == em_wsc_msg_type_m2) {
                autoconfig_wsc_m2();
            }

            break;

        case em_msg_type_topo_disc:
            topo_disc();

            break;

        case em_msg_type_topo_notif:
            topo_notif();
            break;

        case em_msg_type_topo_query:
            topo_query();
            break;

        case em_msg_type_topo_resp:
            topo_resp();
            break;

        case em_msg_type_topo_vendor:
            topo_vendor();
            break;

        case em_msg_type_link_metric_query:
            link_metric_query();

            break;

        case em_msg_type_link_metric_resp:
            link_metric_resp();

            break;

        case em_msg_type_autoconf_renew:
            autoconfig_renew();
            break;

        case em_msg_type_ap_cap_query:
            ap_cap_query();
            break;

        case em_msg_type_ap_cap_rprt:
            ap_cap_rprt();
            break;

        case em_msg_type_map_policy_config_req:
            policy_config_req();
            break;

        case em_msg_type_channel_pref_query:
            channel_pref_query();
            break;

        case em_msg_type_channel_pref_rprt:
            channel_pref_rprt();
            break;

        case em_msg_type_channel_sel_req:
            channel_sel_req();
            break;

        case em_msg_type_channel_sel_rsp:
            channel_sel_rsp();
            break;

        case em_msg_type_op_channel_rprt:
            op_channel_rprt();
            break;

        case em_msg_type_client_cap_query:
            client_cap_query();
            break;

        case em_msg_type_client_steering_req:
            client_steering_req();
            break;

        case em_msg_type_client_steering_btm_rprt:
            client_steering_btm_rprt();
            break;


        case em_msg_type_client_assoc_ctrl_req:
            client_assoc_ctrl_req();
            break;

        case em_msg_type_steering_complete:
            steering_complete();
            break;


        case em_msg_type_higher_layer_data:
            higher_layer_data();
            break;


        case em_msg_type_bh_steering_req:
            bh_steering_req();
            break;


        case em_msg_type_bh_steering_rsp:
            bh_steering_rsp();
            break;

	  case em_msg_type_client_cap_rprt:
            client_cap_rprt();
            break;

        case em_msg_type_ap_metrics_query:
            ap_metrics_query();
            break;

        case em_msg_type_ap_metrics_rsp:
            ap_metrics_rsp();
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            sta_link_metrics_query();
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            sta_link_metrics_rsp();
            break;

        case em_msg_type_unassoc_sta_link_metrics_query:
            unassoc_sta_link_metrics_query();
            break;

        case em_msg_type_unassoc_sta_link_metrics_rsp:
            unassoc_sta_link_metrics_rsp();
            break;

        case em_msg_type_beacon_metrics_query:
            beacon_metrics_query();
            break;

        case em_msg_type_beacon_metrics_rsp:
            beacon_metrics_rsp();
            break;

        case em_msg_type_combined_infra_metrics:
            combined_infra_metrics();
            break;


        case em_msg_type_channel_scan_req:
            channel_scan_req();
            break;


        case em_msg_type_qos_mgmt_notif:
            qos_mgmt_notif();
            break;

        case em_msg_type_anticipated_channel_usage_rprt:
            anticipated_channel_usage_rprt();
            break;

        case em_msg_type_anticipated_channel_pref:
            anticipated_channel_pref();
            break;

        case em_msg_type_agent_list:
            agent_list();
            break;

        case em_msg_type_failed_conn:
            failed_conn();
            break;

        case em_msg_type_dpp_bootstrap_uri_notif:
            dpp_bootstrap_uri_notif();
            break;

        case em_msg_type_1905_encap_eapol:
            i1905_encap_eapol();
            break;

        case em_msg_type_chirp_notif:
            chirp_notif();
            break;

        case em_msg_type_bss_config_res:
            bss_config_res();
            break;


        case em_msg_type_bss_config_rsp:
            bss_config_rsp();
            break;

        case em_msg_type_bss_config_req:
            bss_config_req();
            break;


        case em_msg_type_channel_scan_rprt:
            channel_scan_rprt();
            break;

        case em_msg_type_dpp_cce_ind:
            dpp_cce_ind();
            break;

        case em_msg_type_1905_rekey_req:
            i1905_rekey_req();
            break;

        case em_msg_type_1905_decrypt_fail:
            i1905_decrypt_fail();
            break;

        case em_msg_type_cac_term:
            cac_term();
            break;

        case em_msg_type_client_disassoc_stats:
            client_disassoc_stats();
            break;

        case em_msg_type_svc_prio_req:
            svc_prio_req();
            break;

        case em_msg_type_err_rsp:
            err_rsp();
            break;

        case em_msg_type_assoc_status_notif:
            assoc_status_notif();
            break;

        case em_msg_type_tunneled:
            tunneled();
            break;
	case em_msg_type_bh_sta_cap_query:
            bh_sta_cap_query();
            break;

        case em_msg_type_bh_sta_cap_rprt:
            bh_sta_cap_rprt();
            break;

        case em_msg_type_proxied_encap_dpp:
            proxied_encap_dpp();
            break;

        case em_msg_type_direct_encap_dpp:
            direct_encap_dpp();
            break;

        case em_msg_type_reconfig_trigger:
            reconfig_trigger();
            break;

        case em_msg_type_cac_req:
            cac_req();
            break;

        case em_msg_type_ap_mld_config_req:
            ap_mld_config_req();
            break;

        case em_msg_type_ap_mld_config_resp:
            ap_mld_config_rsp();
            break;

        case em_msg_type_1905_ack:
            i1905_ack();
            break;

        default:
            printf("\ninvalid message type\n");
            break;
    }
}


extern char *__progname;
#define em_printfout(format, ...)  em_util_print(EM_LOG_LVL_INFO, EM_STDOUT, __FILE__, __LINE__, format, ##__VA_ARGS__)// general log

void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...)
{
        char buff[256] = {0};
        char time_buff[128] = {0};
        va_list list;
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
        pid_t pid;
#endif

        const char *severity;
        auto [fp, module_filename] = get_module_log_fd_name(module, level);
        if (fp == NULL) return;

        switch (level) {
                case EM_LOG_LVL_INFO:
                        severity = "INFO";
                        break;
                case EM_LOG_LVL_ERROR:
                        severity = "ERROR";
                        break;
                case EM_LOG_LVL_DEBUG:
                        severity = "DEBUG";
                        break;
                default:
                        severity = "UNKNOWN";
                        break;
        }

        get_formatted_time_em(time_buff);
        snprintf(buff, sizeof(buff), "[%s] %s %s:%s:%d: %s: ", __progname ? __progname : "", time_buff, module_filename.c_str(), func, line, severity);
        fprintf(fp, "%s", buff);

        va_start(list, format);
        vfprintf(fp, format, list);
        va_end(list);

        fprintf(fp, "\n");

        fflush(fp);
        if (fp != stdout) fclose (fp);
}

void dm_easy_mesh_t::set_db_cfg_param(db_cfg_type_t cfg_type, const char *criteria)
{
        unsigned int num = cfg_type;
        unsigned int index = 0;

        while (num % 2 == 0) {
                num /= 2;
                index++;
        }

        if (num != 1) {
                return;
        }

        m_db_cfg_param.db_cfg_type |= static_cast<unsigned int> (cfg_type);
        strncpy(m_db_cfg_param.db_cfg_criteria[index], criteria, strlen(criteria));
}

void     *hash_map_get_first    (hash_map_t *map)
{
    hash_element_t *he;
    element_t    *e;
    if (map == NULL) {
        return NULL;
    }
    map->itr = NULL;

    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    map->itr = e;
    he = (hash_element_t *) e->data;
    if(he == NULL) {
        return NULL;
    }
    return he->data;
}

void     *hash_map_get_next    (hash_map_t *map, void *data)
{
    hash_element_t *he;
    element_t *e;

    if (map == NULL) {
        return NULL;
    }
    if (map->itr != NULL) {
        if (map->itr->data != NULL) {
            he = (hash_element_t *) map->itr->data;
            if (he->data == data) {
                map->itr = map->itr->next;
                if (map->itr == NULL) {
                    return NULL;
                } else {
                    he = (hash_element_t *) map->itr->data;
                    if (he == NULL) {
                        return NULL;
                    }
                    return he->data;
                }
            }
        }
    }
    //full search
    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    while (e != NULL) {
        if (e->data != NULL) {
            he = (hash_element_t *) e->data;
            if (he->data == data) {
                map->itr = e->next;
                if (map->itr == NULL) {
                    return NULL;
                } else {
                    he = (hash_element_t *) map->itr->data;
                    if (he == NULL) {
                        return NULL;
                    }
                    return he->data;
                }
            }
        }
        e = e->next;
    }
    return NULL;
}

dm_sta_t *dm_easy_mesh_t::find_sta(mac_address_t sta_mac, bssid_t bssid)
{
    dm_sta_t *sta;

    sta = static_cast<dm_sta_t *> (hash_map_get_first(m_sta_map));
    while (sta != NULL) {
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) &&
                        (memcmp(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t)) == 0)) {
            return sta;
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(m_sta_map, sta));
    }

    return NULL;
}

int em_metrics_t::handle_assoc_sta_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_link_metrics_t *sta_metrics;
    em_assoc_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = reinterpret_cast<em_assoc_sta_link_metrics_t *> (buff);

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.est_dl_rate = metrics->est_mac_data_rate_dl;
        sta->m_sta_info.est_ul_rate = metrics->est_mac_data_rate_ul;
        sta->m_sta_info.rcpi = metrics->rcpi;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_ext_link_metrics_t     *sta_metrics;
    em_assoc_ext_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = reinterpret_cast<em_assoc_sta_ext_link_metrics_t *> (buff);

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_ext_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.last_dl_rate = metrics->last_data_dl_rate;
        sta->m_sta_info.last_ul_rate = metrics->last_data_ul_rate;
        sta->m_sta_info.util_rx = metrics->util_receive;
        sta->m_sta_info.util_tx = metrics->util_transmit;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff, unsigned int len)
{
    em_vendor_specific_t *vendor_metrics = reinterpret_cast<em_vendor_specific_t *> (buff);
    em_vendor_data_t *vendor_data = vendor_metrics->data;
    em_assoc_sta_vendor_link_metrics_t *sta_metrics;
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();
    sta_metrics = reinterpret_cast<em_assoc_sta_vendor_link_metrics_t *> (vendor_data->vendor_data);

    sta = dm->find_sta(sta_metrics->sta_mac, sta_metrics->bssid);
    if (sta != NULL && len >= sizeof(em_assoc_sta_vendor_link_metrics_t)) {
        strncpy(sta->m_sta_info.sta_client_type, sta_metrics->sta_client_type, sizeof(sta->m_sta_info.sta_client_type));
    }

    return 0;
}

em_bss_info_t *dm_easy_mesh_t::get_bss_info_with_mac(mac_address_t mac)
{
        unsigned int i = 0;

        for (i = 0; i < m_num_bss; i++) {
                if (memcmp(m_bss[i].m_bss_info.bssid.mac, mac, sizeof(mac_address_t)) == 0) {
                        return &m_bss[i].m_bss_info;
                }
        }
        return NULL;
}


int em_metrics_t::handle_ap_metrics_tlv(unsigned char *buff, bssid_t get_bssid)
{
    em_ap_metric_t *ap_metrics = reinterpret_cast<em_ap_metric_t *> (buff);
    em_bss_info_t *bss = get_data_model()->get_bss_info_with_mac(ap_metrics->bssid);
    mac_addr_str_t bss_str;

    memcpy(get_bssid, ap_metrics->bssid, sizeof(mac_addr_t));
    if (bss != NULL) {
        bss->numberofsta = htons(ap_metrics->num_sta);
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
    } else {
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
        printf("%s:%d BSS not found: %s\n", __func__, __LINE__, bss_str);
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_traffic_stats(unsigned char *buff, bssid_t bssid)
{
    em_assoc_sta_traffic_stats_t        *sta_metrics;
    dm_sta_t *sta;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();
    sta_metrics = reinterpret_cast<em_assoc_sta_traffic_stats_t *> (buff);

    sta = dm->find_sta(sta_metrics->sta_mac, bssid);
    if (sta == NULL) {
        em_printfout("sta not found: %s for bssid: %s", util::mac_to_string(sta_metrics->sta_mac).c_str(),
            util::mac_to_string(bssid).c_str());
        return -1;
    }

    sta->m_sta_info.bytes_tx        = sta_metrics->tx_bytes;
    sta->m_sta_info.bytes_rx        = sta_metrics->rx_bytes;
    sta->m_sta_info.pkts_tx         = sta_metrics->tx_pkts;
    sta->m_sta_info.pkts_rx         = sta_metrics->rx_pkts;
    sta->m_sta_info.errors_tx       = sta_metrics->tx_pkt_errors;
    sta->m_sta_info.errors_rx       = sta_metrics->rx_pkt_errors;
    sta->m_sta_info.retrans_count   = sta_metrics->retx_cnt;

    return 0;
}

int em_metrics_t::handle_ap_metrics_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    dm_easy_mesh_t  *dm;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bssid_t bssid;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_ap_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: AP Metrics metrics response msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    tlv_start =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_metrics) {
            handle_ap_metrics_tlv(tlv->value, bssid);
        }
        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_ext_metric) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_radio_metric) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_traffic_sts) {
            //todo: bug fix to find sta
            handle_assoc_sta_traffic_stats(tlv->value, bssid);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_wifi6_sta_rprt) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len));
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    dm->set_db_cfg_param(db_cfg_type_sta_metrics_update, "");
    set_state(em_state_ctrl_configured);

    return 0;
}


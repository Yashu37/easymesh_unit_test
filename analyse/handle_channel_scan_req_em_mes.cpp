#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "common.h"

/* Copied from upstream em_msg.cpp (PR #818 head 884192c) */
bool em_msg_t::get_radio_id(mac_address_t *mac)
{
    em_tlv_t    *tlv;
    unsigned int len;
	unsigned int num_radios = 0;
    em_ap_radio_basic_cap_t *rd_basic_cap;
    em_ap_radio_advanced_cap_t  *rd_adv_cap;
    em_ap_ht_cap_t *rd_ht_cap;
    em_ap_vht_cap_t *rd_vht_cap;
    em_ap_he_cap_t *rd_he_cap;
    em_ap_op_bss_t  *ap;
    
	em_ap_op_bss_radio_t    *radio;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while (len > 0) {
        if (len < sizeof(em_tlv_t)) {
            return false;
        }
        if ((sizeof(em_tlv_t) + ntohs(tlv->len)) > len) {
            return false;
        }
        if (tlv->type == em_tlv_type_channel_scan_req &&
            ntohs(tlv->len) < sizeof(em_channel_scan_req_t)) {
            return false;
        }
        if (tlv->type == em_tlv_type_eom) {
            break;
        }
        if (tlv->type == em_tlv_type_radio_id) {
            memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;    
        } else if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
            rd_basic_cap = reinterpret_cast<em_ap_radio_basic_cap_t *> (tlv->value);
            memcpy(mac, &rd_basic_cap->ruid, sizeof(mac_address_t));
            return true;    
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap) {
            rd_adv_cap = reinterpret_cast<em_ap_radio_advanced_cap_t *> (tlv->value);
            memcpy(mac, &rd_adv_cap->ruid, sizeof(mac_address_t));
            return true;    

        } else if (tlv->type == em_tlv_type_ht_cap) {
            rd_ht_cap = reinterpret_cast<em_ap_ht_cap_t *> (tlv->value);
            memcpy(mac, &rd_ht_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_vht_cap) {
            rd_vht_cap = reinterpret_cast<em_ap_vht_cap_t *>(tlv->value);
            memcpy(mac, &rd_vht_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_he_cap) {
            rd_he_cap = reinterpret_cast<em_ap_he_cap_t *> (tlv->value);
            memcpy(mac, &rd_he_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_operational_bss) {
			ap = reinterpret_cast<em_ap_op_bss_t *> (tlv->value);
			if (ap->radios_num >= 1) {
				radio = ap->radios;
				memcpy(mac, &radio->ruid, sizeof(mac_address_t));
				return true;	
			} 
        } else if (tlv->type == em_tlv_type_channel_pref) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;	
		} else if (tlv->type == em_tlv_type_channel_sel_resp) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;
		} else if (tlv->type == em_tlv_type_op_channel_report) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;
		} else if (tlv->type == em_tlv_type_channel_scan_req) {
			memcpy(&num_radios, tlv->value + sizeof(unsigned char), sizeof(unsigned char));
			if (num_radios != 0) {
				memcpy(mac, tlv->value + 2*sizeof(unsigned char), sizeof(mac_address_t));
				return true;
			} else {
				return false;
			}
		} else if (tlv->type == em_tlv_type_channel_scan_rslt) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;
		} else if (tlv->type == em_tlv_type_radio_metric) {
            memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_bh_sta_radio_cap) {
            memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;
        }

        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

/* Copied from upstream em_msg.cpp */
em_msg_t::em_msg_t(unsigned char *tlvs, unsigned int len)
{
    m_buff  = tlvs;
    m_len = len;
}

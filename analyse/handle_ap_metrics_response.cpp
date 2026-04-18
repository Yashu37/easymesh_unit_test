#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

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

#if 1
unsigned int em_msg_t::validate(char *errors[])
{
	em_tlv_t *tlv;
	unsigned int i, len;
	bool validation = true;

	for (i = 0; i < m_num_tlv; i++) {
		tlv =  reinterpret_cast<em_tlv_t *> (m_buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
		len = m_len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));


		while (((len > 0) && (len >= sizeof(em_tlv_t)) && tlv && (tlv->type != em_tlv_type_eom))) {
			//printf("\n--- TLV DEBUG ---\n");
			//printf("TLV PTR = %p\n", tlv);
			//printf("TYPE = 0x%02x LEN = %u\n", tlv->type, ntohs(tlv->len));
			//printf("Remaining len = %u\n", len);

			if ((sizeof(em_tlv_t) + ntohs(tlv->len)) > len) {
				printf(" INVALID: TLV exceeds remaining buffer\n");
				validation = false;   // mark invalid TLV chain
				break;
			}

			if (tlv->type == m_tlv_member[i].m_type) {
				m_tlv_member[i].m_present = true;
				break;
			}

			len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
			tlv = reinterpret_cast<em_tlv_t *> ((reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + ntohs(tlv->len)));
		}

		//  NEW CHECK: ensure safe access before using tlv->len
		unsigned int safe_len = 0;
		if (len >= sizeof(em_tlv_t)) {
			safe_len = ntohs(tlv->len);
		}

		//printf("expected=%u actual=%lu\n", m_tlv_member[i].m_tlv_length,sizeof(em_tlv_t) + safe_len);

		if ((m_tlv_member[i].m_requirement == mandatory) &&((m_tlv_member[i].m_present == false)||((sizeof(em_tlv_t) + safe_len) < static_cast<size_t> (m_tlv_member[i].m_tlv_length)))) {
			strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
			m_num_errors++;
			errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
			validation = false;
			if(m_tlv_member[i].m_present == false) {
				printf("%s:%d; TLV not present\n", __func__, __LINE__);
			}

			printf("DEBUG [%s:%d:%s] LOOP: tlv_ptr=%p len_remaining=%u\n", __FILE__, __LINE__, __func__, (void*)tlv, len);
			printf("validate() = %u\n", validation);

			if (tlv && ((sizeof(em_tlv_t) + safe_len) < static_cast<size_t> (m_tlv_member[i].m_tlv_length))) {
				printf("%s:%d; TLV type: 0x%04x Length: %d, length validation error\n", __func__, __LINE__, tlv->type, ntohs(tlv->len));
			}
		}

		if ((m_tlv_member[i].m_requirement == bad) && (m_tlv_member[i].m_present == true)) {
			strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]));
			m_num_errors++;
			errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
			printf("%s:%d; TLV type: 0x%04x Length: %d, presence validation error, profile: %d\n", __func__, __LINE__, tlv->type, ntohs(tlv->len), m_profile);
			validation = false;
		}
	}

	for (i = 0; i < EM_MAX_TLV_MEMBERS; i++) {
		if (errors[i] != NULL) {
			printf("Failed TLV [%d]: %s\n",(i+1),errors[i]);
		}
	}

	printf("validate() = %u\n", validation);

	return validation;
}
#endif

//wanted 
#if 0
dm_sta_t *dm_easy_mesh_t::insert_sta(mac_address_t sta_mac, bssid_t bssid)
{
	unsigned char *ptr = (unsigned char *)bssid;

	// move after BSSID
	ptr += 6;

	// force reading next fields (may be invalid)
	uint32_t time_delta = *(uint32_t *)ptr;
	ptr += 4;

	uint32_t dl = *(uint32_t *)ptr;
	ptr += 4;

	uint32_t ul = *(uint32_t *)ptr;
	ptr += 4;

	uint8_t rcpi = *ptr;

	// invalid → crash
	if (time_delta == 0 || dl == 0 || ul == 0) {
		printf("FATAL: Invalid TLV → crash\n");
		*(volatile int *)0 = 0;
	}

	// ---- valid → return dummy
	static dm_sta_t dummy;

	memcpy(dummy.m_sta_info.id, sta_mac, sizeof(mac_address_t));
	memcpy(dummy.m_sta_info.bssid, bssid, sizeof(mac_address_t));

	return &dummy;
}
#endif

dm_sta_t *dm_easy_mesh_t::insert_sta(mac_address_t sta_mac, bssid_t bssid)
{
        unsigned char *ptr = (unsigned char *)bssid;

        // BSSID (6 bytes)
        unsigned char *bssid_ptr = ptr;
        ptr += 6;

        // mandatory metrics (total 16 bytes)
        uint32_t dl = *(uint32_t *)ptr;
        ptr += 4;

        uint32_t ul = *(uint32_t *)ptr;
        ptr += 4;

        uint32_t rx = *(uint32_t *)ptr;
        ptr += 4;

        uint32_t tx = *(uint32_t *)ptr;
        ptr += 4;

        // invalid → crash
        if (dl == 0 || ul == 0 || rx == 0 || tx == 0) {
                printf("FATAL: Invalid TLV → crash\n");
                *(volatile int *)0 = 0;
        }

        static dm_sta_t dummy;

        memcpy(dummy.m_sta_info.id, sta_mac, sizeof(mac_address_t));
        memcpy(dummy.m_sta_info.bssid, bssid_ptr, sizeof(mac_address_t));

        return &dummy;
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

//	 return NULL;
	return insert_sta(sta_mac, bssid);
}

int em_metrics_t::handle_assoc_sta_link_metrics_tlv(unsigned char *buff,
		unsigned int tlv_len)
{
	em_assoc_sta_link_metrics_t *sta_metrics;
	em_assoc_link_metrics_t *metrics;
	dm_sta_t *sta;
	unsigned int i;
	dm_easy_mesh_t *dm;

	if (buff == NULL || tlv_len == 0 || tlv_len < 7) {
		printf("Invalid input: buff=%p tlv_len=%u\n", buff, tlv_len);
		return -1;
	}

	dm = get_data_model();

	printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
	sta_metrics = reinterpret_cast<em_assoc_sta_link_metrics_t *>(buff);
	printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);

	//  ADD THIS CHECK (only addition)

	unsigned int k = sta_metrics->num_bssids;
	unsigned int expected_len = 7 + (k * sizeof(em_assoc_link_metrics_t));

	if (tlv_len != expected_len) {
		printf("Invalid TLV: k=%u expected=%u actual=%u\n", k, expected_len, tlv_len);
		return -1;
	}

	printf("k(num_bssids): %u\n", sta_metrics->num_bssids);

	printf("STA MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			sta_metrics->sta_mac[0], sta_metrics->sta_mac[1],
			sta_metrics->sta_mac[2], sta_metrics->sta_mac[3],
			sta_metrics->sta_mac[4], sta_metrics->sta_mac[5]);

	for (i = 0; i < sta_metrics->num_bssids; i++) {
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
		metrics = &sta_metrics->assoc_link_metrics[i];
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);

		printf("BSSID[%u]: %02x:%02x:%02x:%02x:%02x:%02x\n",
				i,
				metrics->bssid[0], metrics->bssid[1],
				metrics->bssid[2], metrics->bssid[3],
				metrics->bssid[4], metrics->bssid[5]);

		sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
		if (sta == NULL) {
			printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
			continue;
		}

		printf("DL: %u UL: %u RCPI: %u\n",
				metrics->est_mac_data_rate_dl,
				metrics->est_mac_data_rate_ul,
				metrics->rcpi);

		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
		sta->m_sta_info.est_dl_rate = metrics->est_mac_data_rate_dl;
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
		sta->m_sta_info.est_ul_rate = metrics->est_mac_data_rate_ul;
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
		sta->m_sta_info.rcpi = metrics->rcpi;
		printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
	}

	printf("Function: %s Line: %d tlv_len: %u\n", __func__, __LINE__, tlv_len);
	return 0;
}

int em_metrics_t::handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
	em_assoc_sta_ext_link_metrics_t     *sta_metrics;
	em_assoc_ext_link_metrics_t *metrics;
	dm_sta_t *sta;
	unsigned int i;
	dm_easy_mesh_t  *dm;

	if (buff == NULL || tlv_len == 0 || tlv_len < 7) {
                printf("Invalid input: buff=%p tlv_len=%u\n", buff, tlv_len);
                return -1;
        }

	dm = get_data_model();

	sta_metrics = reinterpret_cast<em_assoc_sta_ext_link_metrics_t *> (buff);

/*	unsigned int k = sta_metrics->num_bssids;
	unsigned int expected_len = 7 + (k * sizeof(em_assoc_ext_link_metrics_t));
*/
	unsigned int k = sta_metrics->num_bssids;

	unsigned int expected_len =
	offsetof(em_assoc_sta_ext_link_metrics_t, assoc_ext_link_metrics) +
	(k * sizeof(em_assoc_ext_link_metrics_t));

	if (tlv_len != expected_len) {
		printf("Invalid TLV: k=%u expected=%u actual=%u\n", k, expected_len, tlv_len);
		return -1;
	}

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

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_ap_metrics) {
			handle_ap_metrics_tlv(tlv->value, bssid);
		}
		tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_ap_ext_metric) {
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_radio_metric) {
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_assoc_sta_traffic_sts) {
			//todo: bug fix to find sta
			handle_assoc_sta_traffic_stats(tlv->value, bssid);
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		unsigned int tlv_len = ntohs(tlv->len);
		if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
			handle_assoc_sta_link_metrics_tlv(tlv->value, tlv_len);
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t>(tlv_len));
		tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + tlv_len);
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		unsigned int tlv_len = ntohs(tlv->len);
		if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
			handle_assoc_sta_ext_link_metrics_tlv(tlv->value, tlv_len);
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_assoc_wifi6_sta_rprt) {
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	tlv = tlv_start;
	tmp_len = base_len;

	while (((tmp_len > 0) && (tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom))) {
		if (tlv->type == em_tlv_type_vendor_specific) {
			handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len));
		}
		tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
	}

	dm->set_db_cfg_param(db_cfg_type_sta_metrics_update, "");
	set_state(em_state_ctrl_configured);

	return 0;
}


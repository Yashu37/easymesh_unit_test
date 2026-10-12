#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

#if 1
int em_metrics_t::handle_unassoc_sta_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
	dm_easy_mesh_t *dm = get_data_model();

	unsigned short pos = 0;
	mac_addr_str_t mac_str;

	if (tlv_len < 2) {
		em_printfout("%s:%d Invalid TLV length=%u\n", __func__, __LINE__, tlv_len);
		return -1;
	}

	unsigned char op_class = buff[pos++];
	unsigned char num_sta  = buff[pos++];

#if 1
	unsigned int expected_len =
		2 + (num_sta * sizeof(em_unassoc_sta_metric_t));

	if (tlv_len != expected_len) {
		em_printfout("%s:%d Malformed Unassoc STA Link Metrics TLV: "
				"num_sta=%u expected_len=%u actual_len=%u\n",
				__func__, __LINE__, num_sta,
				expected_len, tlv_len);
		return -1;
	}
#endif
	for (unsigned int i = 0; i < num_sta; i++)
	{
		if (pos + sizeof(em_unassoc_sta_metric_t) > tlv_len) {
			em_printfout("%s:%d Malformed Unassoc STA Link Metrics TLV: num_sta=%u parsed=%u tlv_len=%u\n", __func__, __LINE__, num_sta, i,tlv_len);
			return -1;
		}
		em_unassoc_sta_metric_t *metric = reinterpret_cast<em_unassoc_sta_metric_t *>(buff + pos);

		unsigned int idx = dm->m_num_unassoc_sta_metrics;

		if (idx >= EM_MAX_UNASSOC_STA)
		{
			em_printfout("%s:%d Max STA limit reached",__func__, __LINE__);
			break;
		}

		memcpy(dm->m_unassoc_sta_metrics[idx].sta_mac, metric->sta_mac,sizeof(mac_address_t));
		dm->m_unassoc_sta_metrics[idx].channel = metric->channel;
		dm->m_unassoc_sta_metrics[idx].op_class = op_class;
		dm->m_unassoc_sta_metrics[idx].rcpi = metric->rcpi;
		dm->m_unassoc_sta_metrics[idx].time_delta = ntohl(metric->time_delta);
		dm_easy_mesh_t::macbytes_to_string(metric->sta_mac, mac_str);

		dm->m_num_unassoc_sta_metrics++;

		pos += sizeof(em_unassoc_sta_metric_t);
	}
	return 0;
}

#endif


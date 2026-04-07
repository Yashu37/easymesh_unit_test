#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"

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
/*
#define EM_ASSERT_MSG_FALSE(x, ret, errMsg, ...) \
    if(x) { \
        em_printfout(errMsg, ## __VA_ARGS__); \
        return ret; \
    }

#define EM_ASSERT_MSG_TRUE(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_NOT_NULL(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)


em_tlv_t *em_msg_t::get_first_tlv(em_tlv_t* tlvs_buff, unsigned int buff_len)
{

    if (tlvs_buff == NULL || buff_len == 0) {
    em_printfout("%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    em_printfout("buff_len = %d", buff_len);
   
#if 1    
    if (buff_len < sizeof(em_tlv_t)) {
	    em_printfout("Truncated packet: not enough space for TLV length field\n");
	    return NULL;
    }
#endif

    em_printfout("%s:%d\n", __func__, __LINE__);
    em_tlv_t *tlv = tlvs_buff;
    uint16_t tlv_len = ntohs(tlv->len);

    em_printfout("tlv->type = %x, %s:%d\n", tlv->type, __func__, __LINE__);
    if (tlv_len == 0 || tlv_len + sizeof(em_tlv_t) > buff_len) {
    em_printfout("%s:%d\n", __func__, __LINE__);
        return NULL; // Invalid TLV length or buffer too small
    }

    em_printfout("%s:%d\n", __func__, __LINE__);
    return tlv;
}

em_tlv_t *em_msg_t::get_next_tlv(em_tlv_t* tlv, em_tlv_t* tlvs_buff, unsigned int buff_len)
{
    EM_ASSERT_NOT_NULL(tlv, NULL, "TLV is NULL");
    EM_ASSERT_NOT_NULL(tlvs_buff, NULL, "Buffer is NULL");
    EM_ASSERT_MSG_TRUE(buff_len > 0, NULL, "Buffer length is zero");

    uint8_t* main_tlvs_buff = reinterpret_cast<uint8_t*>(tlvs_buff);

    // Calculate offset of current TLV from buffer start
    long int signed_offset = reinterpret_cast<uint8_t*>(tlv) - main_tlvs_buff;
    EM_ASSERT_MSG_TRUE(signed_offset >= 0, NULL, "TLV is before buffer start");
    size_t offset = static_cast<size_t>(signed_offset);
    EM_ASSERT_MSG_TRUE(offset < buff_len, NULL, "TLV offset exceeds buffer length");

    if (buff_len < sizeof(em_tlv_t)) {
            em_printfout("Truncated packet: not enough space for TLV length field\n");
            return NULL;
    }

    // Calculate the size of the current TLV (header + data)
    uint16_t current_tlv_size = sizeof(em_tlv_t) + ntohs(tlv->len);

    // Shift the offset by the current TLV
    offset += current_tlv_size;
    if (offset >= buff_len) {
        return NULL; // No more TLVs
    }

    // Position buffer pointer to start of next TLV
    em_tlv_t* next_tlvs_buff = reinterpret_cast<em_tlv_t*>(main_tlvs_buff + offset);
    unsigned int next_tlvs_buff_len = buff_len - static_cast<unsigned int>(offset);

    // Use get_first_tlv to validate and return the next TLV
    return get_first_tlv(next_tlvs_buff, next_tlvs_buff_len);
}
*/

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

int em_capability_t::handle_bsta_radio_cap(unsigned char *tlv_buff, unsigned int tlv_len)
{
    if (!tlv_buff)
    {
        return -1;
    }

    if (!tlv_len || ((tlv_len != sizeof(em_bh_sta_radio_cap_t)) && (tlv_len != offsetof(em_bh_sta_radio_cap_t, bsta_addr))))
    {
        em_printfout("Invalid TLV length. Must be %d or %d for bsta radio cap TLV",
                     (int) offsetof(em_bh_sta_radio_cap_t, bsta_addr),
                     (int)sizeof(em_bh_sta_radio_cap_t));
        return -1;
    }

//    const em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<const em_bh_sta_radio_cap_t*>(tlv_buff);

    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(tlv_buff);
    std::string ruid_str = util::mac_to_string(bsta_radio_cap->ruid);
    em_printfout("Rcvd BSTA Cap, for radio: %s, mac present: %d",
            ruid_str.c_str(),
            bsta_radio_cap->bsta_mac_present);

    if (tlv_len == offsetof(em_bh_sta_radio_cap_t, bsta_addr))
    {
        if (bsta_radio_cap->bsta_mac_present)
        {
            em_printfout("Error: bsta_mac_present is 1 when tlv_len is %d", (int) offsetof(em_bh_sta_radio_cap_t, bsta_addr));
            return -1;
        }
        return 0;
    }

    if (!bsta_radio_cap->bsta_mac_present)
    {
        em_printfout("Error: bsta_mac_present is 0 when tlv_len is %d", (int) sizeof(em_bh_sta_radio_cap_t));
        return -1;
    }

    dm_easy_mesh_t *dm = get_data_model();

    if (!dm) {
        em_printfout("Could not find data model");
        return -1;
    }

    em_device_info_t *dev = dm->get_device_info();
    if (!dev)
    {
            em_printfout("Could not find device in data model");
            return -1;
    }

    em_printfout("Update BSTA Cap for Device id: %s",
                    util::mac_to_string(dev->id.dev_mac).c_str());

    memcpy(dm->m_device.m_device_info.backhaul_sta,
                    bsta_radio_cap->bsta_addr,
                    sizeof(mac_address_t));

    dm->set_db_cfg_param(db_cfg_type_device_list_update, "");

    return 0;
}
int em_capability_t::handle_client_info(unsigned char *tlv_buff, unsigned int tlv_len)
{
    if (!tlv_buff) {
        return -1;
    }

    if (tlv_len != sizeof(em_client_info_t)) {
        em_printfout("Invalid TLV length for client info TLV: received %u, expected %d", tlv_len, (int) sizeof(em_client_info_t));
        return -1;
    }

    const em_client_info_t *client_info = reinterpret_cast<const em_client_info_t *>(tlv_buff);

    dm_easy_mesh_t *dm = get_data_model();

    if (!dm) {
        em_printfout("Could not find data model");
        return -1;
    }

    if (dm->get_colocated() != true) {
        memcpy(dm->m_device.m_device_info.backhaul_mac.mac, client_info->client_mac_addr, sizeof(mac_address_t));
        dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
    }

    return 0;
}

int em_capability_t::process_1905_eth_message(unsigned char *pkt_buff, unsigned int pkt_len, em_tlv_type_t tlv_type,
                                             int (em_capability_t::*handler)(unsigned char*, unsigned int))
{
    em_tlv_t *tlv = NULL;
    unsigned int header_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);

    if (!pkt_buff || !pkt_len || !handler) {
        return -1;
    }

    if (pkt_len <= header_len) {
        return -1;
    }

    // Define the start and total length of the TLV payload area
    em_tlv_t* tlvs_start = reinterpret_cast<em_tlv_t *>(pkt_buff + header_len);
    unsigned int tlvs_len = pkt_len - header_len;

 
    if (tlvs_len >= sizeof(em_tlv_t) && tlvs_start->type == em_tlv_type_eom) {
	    return 0;
    }

    // Get the first TLV using the helper
    tlv = em_msg_t::get_first_tlv(tlvs_start, tlvs_len);

#if 1
    if (!tlv) {
	    return -1;
    }
#endif

    while (tlv != NULL) {
        // End of Message TLV check
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        // Check if this TLV matches the requested type
        if (tlv->type == tlv_type) {
            uint16_t tlv_len = ntohs(tlv->len);
            return (this->*handler)(tlv->value, tlv_len);
        }

        // Advance to the next TLV using the helper
        tlv = em_msg_t::get_next_tlv(tlv, tlvs_start, tlvs_len);
    }

    return 0;
}

int em_capability_t::handle_bsta_cap_report(unsigned char *pkt_buff, unsigned int pkt_len)
{
    int ret = 0;

    em_printfout("Backhaul Sta Capability report message rcvd");

    ret = process_1905_eth_message(pkt_buff, pkt_len,
            em_tlv_type_bh_sta_radio_cap,
            &em_capability_t::handle_bsta_radio_cap);

    if (ret < 0)
	    return ret;
        //em_printfout("Warning: failed to process bh_sta_radio_cap TLV, continuing");

    ret = process_1905_eth_message(pkt_buff, pkt_len,
            em_tlv_type_client_info,
            &em_capability_t::handle_client_info);

    if (ret < 0)
        return ret;

    set_state(em_state_ctrl_configured);
    em_printfout("Cap: Bsta Capability report processed, ctrl configured");

    return ret;
}


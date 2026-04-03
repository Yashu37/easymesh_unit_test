#include <cstring>
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

int em_capability_t::handle_bsta_radio_cap(unsigned char *buff, unsigned int len)
{
    if (!buff)
    {
        em_printfout("buff is NULL\n");
        return -1;
    }

    em_printfout("len = %d\n", len);

    if (!len || (len != 13 && len != 7))
    {
        return -1;
    }

    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(buff);
    std::string ruid_str = util::mac_to_string(bsta_radio_cap->ruid);
    em_printfout("Rcvd BSTA Cap, for radio: %s, mac present: %d",
		    ruid_str.c_str(),
		    bsta_radio_cap->bsta_mac_present);

    dm_easy_mesh_t *dm = get_data_model();

    if (!dm) {
	    em_printfout("Could not find data model");
	    return -1;
    }

    // SAFE MEMCPY AND SAFE PRINT
    if (len == 13 && bsta_radio_cap->bsta_mac_present)
    {
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
    }

    dm->set_db_cfg_param(db_cfg_type_device_list_update, "");

    return 0;
}

int em_capability_t::process_client_info(unsigned char *buff, unsigned int len)
{
    //length check
    if (len != 12) {
        em_printfout("Error: Invalid TLV length (%u)", len);
        return -1;
    }

    // safety check
    if (!buff) {
        em_printfout("Error: buff is NULL");
        return -1;
    }

    dm_easy_mesh_t *dm = get_data_model();

    if (dm && dm->get_colocated() != true) {

        memcpy(dm->m_device.m_device_info.backhaul_mac.mac,
               buff,
               sizeof(mac_address_t));

        dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
    }

    return 0;
}

int em_capability_t::process_tlv_loop(unsigned char *buff, unsigned int len, uint8_t target_type,
                                      int (em_capability_t::*handler)(unsigned char*, unsigned int))
{
    em_tlv_t *tlv;
    unsigned int tmp_len;
    unsigned int header_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);

    if (!buff)
    {
	    em_printfout("buff is NULL\n");
	    return -1;
    }

    if (!len)
    {
	    return -1;
    }

    if (!handler)
    {
            em_printfout("handler is NULL\n");
            return -1;
    }

    if (len <= header_len) {
        em_printfout("Error: Packet too small");
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *>(buff + header_len);
    tmp_len = len - header_len;

    // TLV header check
    if (tmp_len < sizeof(em_tlv_t)) {
        em_printfout("Error: Not enough data for TLV");
        return -1;
    }

    while ((tmp_len >= sizeof(em_tlv_t)) && tlv) {

        uint16_t tlv_len = ntohs(tlv->len);

        // Safety check
        if (tmp_len < sizeof(em_tlv_t) + tlv_len) {
            em_printfout("Error: TLV length exceeds buffer");
            return -1;
        }

        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        // TARGET TLV MATCH
        if (tlv->type == target_type) {

            return (this->*handler)(tlv->value, tlv_len);
        }

        em_printfout("sizeof(em_tlv_t) = %d\n", sizeof(em_tlv_t));
        em_printfout("tlv_len = %d\n", tlv_len);

        tmp_len -= sizeof(em_tlv_t) + tlv_len;

        tlv = reinterpret_cast<em_tlv_t*>(
                reinterpret_cast<unsigned char*>(tlv) +
                sizeof(em_tlv_t) + tlv_len);
    }

    return 0;
}

int em_capability_t::handle_bsta_cap_report(unsigned char *buff, unsigned int len)
{
    int ret = 0;

    em_printfout("Backhaul Sta Capability report message rcvd");

    //BSTA RADIO CAP
    ret = process_tlv_loop(buff, len,
                           em_tlv_type_bh_sta_radio_cap,
                           &em_capability_t::handle_bsta_radio_cap);

    if (ret < 0)
        return ret;

    //CLIENT INFO
    ret = process_tlv_loop(buff, len,
                           em_tlv_type_client_info,
                           &em_capability_t::process_client_info);

    if (ret < 0)
        return ret;

    set_state(em_state_ctrl_configured);

    em_printfout("Cap: Bsta Capability report processed, ctrl configured");

    return ret;
}

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *util::get_date_time_rfc3399(char *buff, unsigned int len)
{
        time_t now;
    struct tm *timeinfo;

    time(&now);
    timeinfo = localtime(&now);

        memset(buff, 0, len);
        strftime(buff, len, "%Y-%m-%dT%H:%M:%SZ", timeinfo);

        return buff;
}

dm_bss_t *dm_easy_mesh_t::get_bss(mac_address_t radio_mac, mac_address_t bss_mac)
{
    unsigned int i;
    dm_bss_t *bss;

    for (i = 0; i < m_num_bss; i++) {
        bss = &m_bss[i];
        if ((memcmp(bss->m_bss_info.bssid.mac, bss_mac, sizeof(mac_address_t)) == 0) &&
                (memcmp(bss->m_bss_info.ruid.mac, radio_mac, sizeof(mac_address_t)) == 0)) {
                        return &m_bss[i];
        }
    }

    return NULL;
}

bool dm_easy_mesh_t::is_ssid_match(const ssid_t &ssid)
{
    em_network_ssid_info_t *info;
    for (unsigned int i = 0; i < m_num_net_ssids; i++) {
        info = &m_network_ssid[i].m_network_ssid_info;
        if (strncmp(info->ssid, ssid, sizeof(info->ssid)) == 0) {
            return true;
        }
    }
    return false;
}

#if 1
int em_configuration_t::handle_ap_operational_bss(unsigned char *buff, unsigned int len)
{
        dm_easy_mesh_t  *dm;
        em_ap_op_bss_t  *ap;
        em_ap_op_bss_radio_t    *radio;
        em_ap_operational_bss_t *bss;
        dm_bss_t *dm_bss;
        bool updated_at_least_one_bss = false;;
        unsigned int i, j;
        unsigned int all_bss_len = 0;
        char time_date[EM_DATE_TIME_BUFF_SZ];

	//FIX 1: 
	if (buff == NULL || len < 1) {
            em_printfout("%s:%d Invalid AP Operational BSS payload length=%u\n", __func__, __LINE__, len);
            return -1;
        }

        dm = get_data_model();

    // first verify that dm has all the radios
    ap = reinterpret_cast<em_ap_op_bss_t *> (buff);
    radio = const_cast<em_ap_op_bss_radio_t *> (ap->radios);
    unsigned int remaining_len = len - 1;

    /* Validate the complete payload before modifying the data model */
    em_ap_op_bss_radio_t *chk_radio = radio;
    em_ap_operational_bss_t *chk_bss;
    unsigned int chk_len = len - 1;

    for (i = 0; i < ap->radios_num; i++) {
        if (chk_len < sizeof(em_ap_op_bss_radio_t)) {
            em_printfout("%s:%d Invalid radio data: remaining=%u\n", __func__, __LINE__, chk_len);
            return -1;
        }
        chk_len -= static_cast<unsigned int> (sizeof(em_ap_op_bss_radio_t));

        chk_bss = chk_radio->bss;
        for (j = 0; j < chk_radio->bss_num; j++) {
            if (chk_len < sizeof(em_ap_operational_bss_t) ||
                chk_len < sizeof(em_ap_operational_bss_t) + chk_bss->ssid_len) {
                em_printfout("%s:%d Invalid BSS data: remaining=%u\n", __func__, __LINE__, chk_len);
                return -1;
            }
            chk_len -= static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + chk_bss->ssid_len);
            chk_bss = reinterpret_cast<em_ap_operational_bss_t *> (reinterpret_cast<unsigned char *> (chk_bss) +
                        sizeof(em_ap_operational_bss_t) + chk_bss->ssid_len);
        }
        chk_radio = reinterpret_cast<em_ap_op_bss_radio_t *> (chk_bss);
    }

        util::get_date_time_rfc3399(time_date, sizeof(time_date));

    for (i = 0; i < ap->radios_num; i++) {
//fix 3
	if (remaining_len < sizeof(mac_address_t) + 1) {
            em_printfout("%s:%d Invalid radio data: remaining=%u\n",
                 __func__, __LINE__, remaining_len);
            return -1;
        }

	remaining_len -= sizeof(mac_address_t) + 1;

        bss = radio->bss;
        all_bss_len = 0;
        for (j = 0; j < radio->bss_num; j++) {
            if (remaining_len < sizeof(em_ap_operational_bss_t)) {
                em_printfout("%s:%d Invalid BSS data: remaining=%u\n", __func__, __LINE__, remaining_len);
                return -1;
            }

            if (remaining_len < sizeof(em_ap_operational_bss_t) + bss->ssid_len) {
                em_printfout("%s:%d Invalid BSS SSID length=%u remaining=%u\n", __func__, __LINE__, bss->ssid_len, remaining_len);
                return -1;
            }

            remaining_len -= sizeof(em_ap_operational_bss_t) + bss->ssid_len;

            dm_bss = dm->get_bss(radio->ruid, bss->bssid);

                        if (dm_bss == NULL) {
				if (dm->m_num_bss >= EM_MAX_BSSS) {
                                    em_printfout("%s:%d Maximum BSS capacity reached: %u\n", __func__, __LINE__, dm->m_num_bss);
                                    return -1;
                                }
                                dm_bss = &dm->m_bss[dm->m_num_bss];
                                dm_bss->init();

                                // fill up id first
                                strncpy(dm_bss->m_bss_info.id.net_id, dm->m_device.m_device_info.id.net_id, sizeof(em_long_string_t));
                                memcpy(dm_bss->m_bss_info.id.dev_mac, dm->m_device.m_device_info.intf.mac, sizeof(mac_address_t));
                                memcpy(dm_bss->m_bss_info.id.ruid, radio->ruid, sizeof(mac_address_t));
                                memcpy(dm_bss->m_bss_info.id.bssid, bss->bssid, sizeof(mac_address_t));

                memcpy(dm_bss->m_bss_info.bssid.mac, bss->bssid, sizeof(mac_address_t));
                memcpy(dm_bss->m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t));
                dm->set_num_bss(dm->get_num_bss() + 1);
                        }
            ssid_t ssid_buf;
            size_t ssid_len = bss->ssid_len;
            if (ssid_len >= sizeof(ssid_buf)) {
                ssid_len = sizeof(ssid_buf) - 1;
            }
            memcpy(ssid_buf, bss->ssid, ssid_len);
            ssid_buf[ssid_len] = '\0';
            if (dm->is_ssid_match(ssid_buf)) {
                strncpy(dm_bss->m_bss_info.ssid, ssid_buf, sizeof(dm_bss->m_bss_info.ssid) - 1);
                dm_bss->m_bss_info.ssid[sizeof(dm_bss->m_bss_info.ssid) - 1] = '\0';
            } else {
                // SSID mismatch, stop processing further.
                em_printfout("%s:%d:SSID mismatch. Stop proceeding. SSID=%s", __func__, __LINE__, ssid_buf);
                return -2;
            }
            dm_bss->m_bss_info.enabled = true;
            strncpy(dm_bss->m_bss_info.timestamp, time_date, sizeof(em_long_string_t));

                        updated_at_least_one_bss = true;

                        all_bss_len += static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + bss->ssid_len);
                        bss = reinterpret_cast<em_ap_operational_bss_t *> (reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
        }

        radio = reinterpret_cast<em_ap_op_bss_radio_t *> (reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);

    }

        if (updated_at_least_one_bss == true) {
                dm->set_db_cfg_param(db_cfg_type_bss_list_update, "");
        }

        return 0;

}
#endif

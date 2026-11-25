/*
 * HANDLER: dm_easy_mesh_t::print_config (fixes 1-3 applied, start fix n / end fix n markers: the net SSID / BSS / radio counts are read
 * through the get_num_network_ssid() / get_num_bss() / get_num_radios() getters, which clamp them to the array sizes (the two getters
 * are fixed in print_config.h like inc/dm_easy_mesh.h); the op class count and the per op class channel count are clamped to their
 * array sizes here; the truncation failure is left original)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ aee6c47): dm_easy_mesh_t::print_config (src/dm/dm_easy_mesh.cpp). Local arrays: the
 * ch_buf[256] of the channel scan loop. The dm_easy_mesh_t stand-in has the members the function reads (net SSIDs, BSSs, radios, radio
 * caps with the real em_channel_scan_cap_radio_t); em_printfout() records every line it prints. The object lives on the heap between
 * poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "print_config.h"

namespace pcf {
box_t *g_box = NULL; std::vector<std::string> g_lines;
std::string util::mac_to_string(unsigned char *mac) { char b[24]; snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return b; }
void em_printfout_fn(const char *fmt, ...)
{ char b[2048]; va_list a; va_start(a, fmt); vsnprintf(b, sizeof(b), fmt, a); va_end(a); g_lines.push_back(b); }

/* --- copied verbatim --- */
void dm_easy_mesh_t::print_config()
{
    unsigned int i;
    int transmit_power_limit;

	em_printfout("Network:%s", m_network.m_net_info.id);
    em_printfout("Controller MAC:%s\tController AL MAC:%s\tAgent AL MAC:%s\n",
            util::mac_to_string(get_controller_interface_mac()).c_str(),
            util::mac_to_string(get_ctrl_al_interface_mac()).c_str(),
            util::mac_to_string(get_agent_al_interface_mac()).c_str());
    em_printfout("Manufacturer:%s\tManufacturere Model:%s\tSoftwareVersion:%s\n",
            get_manufacturer(), get_manufacturer_model(), get_software_version());

/* start fix 1 */
    for (i = 0; i < get_num_network_ssid(); i++) {
/* end fix 1 */
        em_printfout("Data Model SSID[%d]: %s\n", i, m_network_ssid[i].m_network_ssid_info.ssid);
    }

    for (i = 0; i < m_num_opclass; i++) {
        //em_printfout("OpClass[%d] id.ruid: %s id.type: %d id.index: %d Channel : %d Op_class : %d num_channel : %d Max tx_p : %d\n\n", 
		//		i, util::mac_to_string(m_op_class[i].m_op_class_info.id.ruid).c_str(), m_op_class[i].m_op_class_info.id.type, 
		//		m_op_class[i].m_op_class_info.id.op_class, m_op_class[i].m_op_class_info.channel, 
		//		m_op_class[i].m_op_class_info.op_class, m_op_class[i].m_op_class_info.num_channels, m_op_class[i].m_op_class_info.max_tx_power);
    }

    em_printfout("No of BSS=%d No of Radios=%d", m_num_bss, m_num_radios);
/* start fix 1 */
    for (i = 0; i < get_num_bss(); i++) {
/* end fix 1 */
        em_printfout("Radio Mac : %s and BSSID : %s", util::mac_to_string(get_bss(i)->get_bss_info()->ruid.mac).c_str(),
            util::mac_to_string(get_bss(i)->get_bss_info()->bssid.mac).c_str());
    }

/* start fix 1 */
    for (i = 0; i < get_num_radios(); i++) {
/* end fix 1 */
        transmit_power_limit = m_radio[i].get_radio_info()->transmit_power_limit;
        em_printfout("Radio Mac: %s, Band: %d, TransmitPowerLimit: %d", util::mac_to_string(m_radio[i].get_radio_info()->intf.mac).c_str(),
            m_radio[i].get_radio_info()->band, transmit_power_limit);
    }

/* start fix 1 */
    for (i = 0; i < get_num_radios(); i++) {
/* end fix 1 */
        em_printfout("Cap Radio[%d]: %s, num_role:%d and su_beam:%d",  i, util::mac_to_string(m_radio_cap[i].get_radio_cap_info()->ruid.mac).c_str(),
            m_radio_cap[i].get_radio_cap_info()->wifi6_cap.num_role,
            m_radio_cap[i].get_radio_cap_info()->wifi6_cap.roles[0].role_tail.su_beam_former);
        em_printfout(
            "HE Cap: RUID:%s MCS_LEN:%u "
            "TXRX_MCS:[TX:0x%04x RX:0x%04x | TX:0x%04x RX:0x%04x | TX:0x%04x RX:0x%04x] "
            "80+80:%u 160:%u RX_SS:%u TX_SS:%u "
            "DL_OFDMA:%u UL_OFDMA:%u DL_MIMO_OFDMA:%u UL_MIMO_OFDMA:%u "
            "UL_MIMO:%u MU_BF:%u SU_BF:%u",
            
            util::mac_to_string(m_radio_cap[i].get_radio_cap_info()->ruid.mac).c_str(),
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_mcs_len,

            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[0].tx_he_mcs,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[0].rx_he_mcs,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[1].tx_he_mcs,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[1].rx_he_mcs,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[2].tx_he_mcs,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_tx_rx_mcs[2].rx_he_mcs,

            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_80_80_mhz,
            m_radio_cap[i].get_radio_cap_info()->he_cap.sprt_160mhz,
            m_radio_cap[i].get_radio_cap_info()->he_cap.max_sprt_rx_streams,
            m_radio_cap[i].get_radio_cap_info()->he_cap.max_sprt_tx_streams,

            m_radio_cap[i].get_radio_cap_info()->he_cap.dl_ofdma_cap,
            m_radio_cap[i].get_radio_cap_info()->he_cap.ul_ofdma_cap,
            m_radio_cap[i].get_radio_cap_info()->he_cap.dl_mimo_ofdma_cap,
            m_radio_cap[i].get_radio_cap_info()->he_cap.ul_mimo_ofdma_cap,

            m_radio_cap[i].get_radio_cap_info()->he_cap.ul_mimo_cap,
            m_radio_cap[i].get_radio_cap_info()->he_cap.mu_beamformer_cap,
            m_radio_cap[i].get_radio_cap_info()->he_cap.su_beamformer_cap
        );
        em_printfout("VHT Cap: RUID:%s TXRX_MCS:[0x%04x 0x%04x] "
            "GI support: 160MHz:%d 80MHz:%d Max RX streams:%d Max TX streams:%d "
            "MU Beamformer:%d SU Beamformer:%d 160MHz:%d 80+80MHz:%d",
            util::mac_to_string(m_radio_cap[i].get_radio_cap_info()->ruid.mac).c_str(),
            m_radio_cap[i].get_radio_cap_info()->vht_cap.sprt_tx_mcs,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.sprt_rx_mcs,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.gi_sprt_160mhz,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.gi_sprt_80mhz,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.max_sprt_rx_streams,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.max_sprt_tx_streams,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.mu_beamformer_cap,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.su_beamformer_cap,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.sprt_160mhz,
            m_radio_cap[i].get_radio_cap_info()->vht_cap.sprt_80_80_mhz
        );
        em_printfout("HT Cap: RUID:%s 40MHz:%d GI 40MHz:%d GI 20MHz:%d Max RX streams:%d Max TX streams:%d",
            util::mac_to_string(m_radio_cap[i].get_radio_cap_info()->ruid.mac).c_str(),
            m_radio_cap[i].get_radio_cap_info()->ht_cap.ht_sprt_40mhz,
            m_radio_cap[i].get_radio_cap_info()->ht_cap.gi_sprt_40mhz,
            m_radio_cap[i].get_radio_cap_info()->ht_cap.gi_sprt_20mhz,
            m_radio_cap[i].get_radio_cap_info()->ht_cap.max_sprt_rx_streams,
            m_radio_cap[i].get_radio_cap_info()->ht_cap.max_sprt_tx_streams
        );
        em_printfout("Channel scan cap: RUID:%s boot only:%d min scan interval:%u scan impact:%u",
            util::mac_to_string(m_radio_cap[i].get_radio_cap_info()->ruid.mac).c_str(),
            m_radio_cap[i].get_radio_cap_info()->ch_scan.boot_only,
            m_radio_cap[i].get_radio_cap_info()->ch_scan.min_scan_interval,
            m_radio_cap[i].get_radio_cap_info()->ch_scan.scan_impact
        );
/* start fix 2 */
        size_t op_classes_num = m_radio_cap[i].get_radio_cap_info()->ch_scan.op_classes_num > EM_MAX_OPCLASS ? EM_MAX_OPCLASS : m_radio_cap[i].get_radio_cap_info()->ch_scan.op_classes_num;
        for (size_t k = 0; k < op_classes_num; k++) {
/* end fix 2 */
            const em_scan_cap_op_class_info_t *oc = &m_radio_cap[i].get_radio_cap_info()->ch_scan.op_classes[k];
            char ch_buf[256] = {0};
            int  ch_buf_pos  = 0;
/* start fix 3 */
            unsigned char oc_num = oc->num > EM_MAX_CHANNELS_IN_LIST ? EM_MAX_CHANNELS_IN_LIST : oc->num;
            for (unsigned char ci = 0; ci < oc_num && ch_buf_pos < static_cast<int>(sizeof(ch_buf)) - 5; ci++) {
/* end fix 3 */
                ch_buf_pos += snprintf(ch_buf + ch_buf_pos, sizeof(ch_buf) - static_cast<size_t>(ch_buf_pos),
                                       "%d ", oc->channels.channel[ci]);
            }
            em_printfout("ch_scan op_class[%zu]: op_class=%d num_channels=%d channels=[%s]",
                k, oc->op_class, oc->num, oc->num > 0 ? ch_buf : "all");
        }
    }
}

void invoke(void) { g_box->dm.print_config(); }
} /* namespace pcf */

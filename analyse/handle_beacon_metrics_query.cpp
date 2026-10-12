#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>

dm_sta_t *dm_easy_mesh_t::get_first_sta(mac_address_t sta_mac)
{
    dm_sta_t *sta;

    sta = static_cast<dm_sta_t *> (hash_map_get_first(m_sta_map));
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            return sta;
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(m_sta_map, sta));
    }

    return NULL;
}

dm_sta_t *dm_easy_mesh_t::get_next_sta(mac_address_t sta_mac, dm_sta_t *psta)
{
    dm_sta_t *sta;
    bool return_next = false;

    sta = static_cast<dm_sta_t *> (hash_map_get_first(m_sta_map));
    while (sta != NULL) {
        if ((return_next == true) && (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            return sta;
        }
        if (sta == psta) {
            return_next = true;
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(m_sta_map, sta));
    }

    return NULL;
}

int dm_easy_mesh_t::name_from_mac_address(const mac_address_t *mac, char *ifname)
{
    struct ifaddrs *ifaddr = NULL, *tmp = NULL;
    struct sockaddr *addr;
    struct sockaddr_ll *ll_addr;
    bool found = false;

    if (getifaddrs(&ifaddr) != 0) {
        printf("%s:%d: Failed to get interfae information\n", __func__, __LINE__);
        return -1;
    }

    tmp = ifaddr;
    while (tmp != NULL) {
        addr = tmp->ifa_addr;
        ll_addr = reinterpret_cast<struct sockaddr_ll*> (tmp->ifa_addr);
        if ((addr != NULL) && (addr->sa_family == AF_PACKET) && (memcmp(ll_addr->sll_addr, mac, sizeof(mac_address_t)) == 0)) {
            snprintf(ifname, IFNAMSIZ, "%s", tmp->ifa_name);
            found = true;
            break;
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(ifaddr);

    return (found == true) ? 0:-1;
}

int em_t::send_frame(unsigned char *buff, unsigned int len, bool multicast)
{
    int ret = 0;
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);

#ifdef AL_SAP
#ifdef DEBUG_MODE
    em_printfout("ORIGINAL_ETH_FRAME:\t");
    util::print_hex_dump(len, buff);
#endif
    AlServiceDataUnit sdu;
    //override destination and source mac addresses
    MacAddress src_mac, dest_mac;
    std::copy(hdr->dst, hdr->dst + ETH_ALEN, dest_mac.begin());
    std::copy(hdr->src, hdr->src + ETH_ALEN, src_mac.begin());

    sdu.setDestinationAlMacAddress(dest_mac);
    sdu.setSourceAlMacAddress(src_mac);

#ifdef DEBUG_MODE
    em_printfout("Destination MAC Address: " MACSTRFMT, MAC2STR(buff));
    em_printfout("Source MAC Address: " MACSTRFMT, MAC2STR(buff+ETH_ALEN));
#endif
    // Copy over the payload, excluding the header
    sdu.setPayload({buff + sizeof(em_raw_hdr_t), buff + len});
    g_sap->serviceAccessPointDataRequest(sdu);
#else
    em_short_string_t   ifname;
    struct sockaddr_ll sadr_ll;
    int sock;
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};


    dm_easy_mesh_t::name_from_mac_address(reinterpret_cast<mac_address_t *>(get_al_interface_mac()), ifname);

    sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return -1;
    }

    sadr_ll.sll_ifindex = static_cast<int>(if_nametoindex(ifname));
    sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr:hdr->dst, sizeof(mac_address_t));

    ret = static_cast<int>(sendto(sock, buff, len, 0, reinterpret_cast<const struct sockaddr*>(&sadr_ll), sizeof(struct sockaddr_ll)));
    close(sock);
#endif

    return ret;
}

int em_metrics_t::handle_beacon_metrics_query(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    size_t sz = 0;

    if (em_msg_t(em_msg_type_beacon_metrics_query, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("Beacon Metrics query message validation failed");
        return -1;
    }

    em_printfout(" Rcvd Beacon Metrics Query");

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    unsigned char *tmp = tlv->value;

    const unsigned int tlv_payload_len = ntohs(tlv->len);
    const unsigned int max_ssid_len = sizeof(em_beacon_metrics_query_t{}.ssid);
    const unsigned int max_ap_channel_rprt = sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt) /
        sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0]);
    const unsigned int max_channels_in_list = sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0].ap_channel_list) /
        sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0].ap_channel_list[0]);
    const unsigned int max_element_ids = sizeof(em_beacon_metrics_query_t{}.element_list.element_list) /
        sizeof(em_beacon_metrics_query_t{}.element_list.element_list[0]);
    const unsigned int min_fixed_len = sizeof(mac_address_t) + sizeof(unsigned char) + sizeof(unsigned char) +
        sizeof(mac_address_t) + sizeof(unsigned char) + sizeof(unsigned char);

    if (tlv_payload_len < min_fixed_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: payload too short (%u)", tlv_payload_len);
        return -1;
    }

    em_beacon_metrics_query_t query_params = {};
    memcpy(query_params.sta_mac_addr, tmp + sz, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.op_class = *(tmp + sz);
    sz += sizeof(unsigned char);
    query_params.channel_num = *(tmp + sz);
    sz += sizeof(unsigned char);
    memcpy(query_params.bssid, tmp + sz, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.rprt_detail = *(tmp + sz);
    sz += sizeof(unsigned char);

    unsigned int ssid_len = *(tmp + sz);
    sz += sizeof(unsigned char);
    if (sz + ssid_len > tlv_payload_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: ssid_len %u exceeds payload %u",
            ssid_len, tlv_payload_len);
        return -1;
    }
    query_params.ssid_len = (ssid_len > max_ssid_len) ? max_ssid_len : ssid_len;
    if (query_params.ssid_len > 0) {
        memcpy(query_params.ssid, tmp + sz, query_params.ssid_len);
    }
    sz += ssid_len;

    if (sz + sizeof(unsigned char) > tlv_payload_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: missing AP Channel Report count");
        return -1;
    }

    unsigned int num_ap_channel_rprt = *(tmp + sz);
    sz += sizeof(unsigned char);
    query_params.num_ap_channel_rprt = (num_ap_channel_rprt > max_ap_channel_rprt) ?
        max_ap_channel_rprt : num_ap_channel_rprt;

    for (unsigned int i = 0; i < num_ap_channel_rprt; i++) {
        unsigned int ap_channel_rprt_len;
        unsigned int num_channels;

        if (sz + sizeof(unsigned char) > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: missing AP Channel Report length");
            return -1;
        }

        ap_channel_rprt_len = *(tmp + sz);
        sz += sizeof(unsigned char);
        if (ap_channel_rprt_len < 1) {
            em_printfout("Malformed Beacon Metrics Query TLV: invalid AP Channel Report length %u",
                ap_channel_rprt_len);
            return -1;
        }
        if (sz + ap_channel_rprt_len > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: AP Channel Report overruns payload");
            return -1;
        }

        num_channels = ap_channel_rprt_len - 1;
        if (i < query_params.num_ap_channel_rprt) {
            query_params.ap_channel_rprt[i].ap_channel_rprt_len =
                (ap_channel_rprt_len > (max_channels_in_list + 1)) ?
                (max_channels_in_list + 1) : ap_channel_rprt_len;
            query_params.ap_channel_rprt[i].ap_channel_op_class = *(tmp + sz);
        }
        sz += sizeof(unsigned char);

        for (unsigned int j = 0; j < num_channels; j++) {
            if (i < query_params.num_ap_channel_rprt && j < max_channels_in_list) {
                query_params.ap_channel_rprt[i].ap_channel_list[j] = *(tmp + sz);
            }
            sz += sizeof(unsigned char);
        }
    }

    if (sz < tlv_payload_len) {
        unsigned int num_element_id = *(tmp + sz);
        sz += sizeof(unsigned char);
        if (sz + num_element_id > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: element list overruns payload");
            return -1;
        }
        query_params.element_list.num_element_id = (num_element_id > max_element_ids) ?
            max_element_ids : num_element_id;
        for (unsigned int i = 0; i < num_element_id; i++) {
            if (i < query_params.element_list.num_element_id) {
                query_params.element_list.element_list[i] = *(tmp + sz);
            }
            sz += sizeof(unsigned char);
        }
    }
  em_printfout("   STA MAC Address: %s", util::mac_to_string(query_params.sta_mac_addr).c_str());
    em_printfout("   Operating Class: %u", query_params.op_class);
    em_printfout("   Channel Number: %u", query_params.channel_num);
    em_printfout("   BSSID: %s", util::mac_to_string(query_params.bssid).c_str());
    em_printfout("   Reporting Detail: %u", query_params.rprt_detail);
    em_printfout("   SSID Length: %u", query_params.ssid_len);
    em_printfout("   SSID: %.*s", query_params.ssid_len, query_params.ssid);


    // Extract message ID for the ACK
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    unsigned short msg_id = ntohs(cmdu->id);
    em_printfout("   msg_id: %u", msg_id);

    // Check if the STA is associated with any BSS on this agent
    dm_easy_mesh_t *dm = get_data_model();
    bool associated = false;
    for (dm_sta_t *sta = dm->get_first_sta(query_params.sta_mac_addr);
            sta != NULL;
            sta = dm->get_next_sta(query_params.sta_mac_addr, sta)) {
        if (sta->m_sta_info.associated) {
            associated = true;
            break;
        }
    }
    if (!associated) {
        em_printfout("STA %s not associated, sending error ACK (reason 0x02)",
            util::mac_to_string(query_params.sta_mac_addr).c_str());
        send_beacon_metrics_query_ack(query_params.sta_mac_addr, msg_id, 0x02);
        return -1;
    }

    // STA is associated — send ACK before forwarding the request to OneWifi
    send_beacon_metrics_query_ack(query_params.sta_mac_addr, msg_id, 0);

    get_mgr()->io_process(em_bus_event_type_beacon_query, reinterpret_cast<unsigned char *>(&query_params), sizeof(em_beacon_metrics_query_t));

    return 0;
}

int em_metrics_t::send_beacon_metrics_query_ack(mac_address_t sta_mac, unsigned short msg_id, unsigned char reason)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_1905_ack);
    cmdu->id   = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    if (reason != 0) {
        // 17.2.36 Error Code TLV
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_error_code;
        unsigned char *ec = tlv->value;
        *ec = reason;
        ec += sizeof(unsigned char);
        memcpy(ec, sta_mac, sizeof(mac_address_t));
        ec += sizeof(mac_address_t);
        tlv->len = htons(static_cast<unsigned short>(sizeof(unsigned char) + sizeof(mac_address_t)));
        tmp += sizeof(em_tlv_t) + sizeof(unsigned char) + sizeof(mac_address_t);
        len += sizeof(em_tlv_t) + sizeof(unsigned char) + sizeof(mac_address_t);
    }

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("Beacon Metrics Query ACK validation failed");
        return -1;
    }

    if (send_frame(buff, len) < 0) {
        em_printfout("Beacon Metrics Query ACK send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics Query ACK sent for msg_id=%u reason=%u", msg_id, reason);
    return static_cast<int>(len);
}


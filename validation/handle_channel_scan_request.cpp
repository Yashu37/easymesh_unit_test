#include <cstring>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <memory>
#include <functional>
#include "./common.h"


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

int em_channel_t::send_1905_ack_message(unsigned short msg_id, bool ack_from)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    if (ack_from == ACK_FROM_CTRL) {
            memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += sizeof(mac_address_t);

            memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += sizeof(mac_address_t);

            memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
            tmp += sizeof(unsigned short);
            len += sizeof(unsigned short);
    } else {
            memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += static_cast<unsigned int> (sizeof(mac_address_t));

            memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += static_cast<unsigned int> (sizeof(mac_address_t));

            memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
            tmp += sizeof(unsigned short);
            len += static_cast<unsigned int> (sizeof(unsigned short));
    }

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        em_printfout("1905 ACK validation failed\n");
        return 0;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("1905 ACK send failed, error:%d\n", errno);
        return 0;
    }
    em_printfout("1905 ACK send success\n");

    return static_cast<int> (len);
}

int em_channel_t::handle_channel_scan_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tlv_len;
    em_channel_scan_req_t *req;
    em_channel_scan_req_op_class_t *op_class;
    em_scan_params_t params;
    unsigned int i;

    memset(&params, 0, sizeof(params));
    unsigned int header_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);

    if (len < header_len + sizeof(em_tlv_t)) {
        em_printfout("%s:%d Invalid Channel Scan Request (len=%u)",__func__, __LINE__, len);
        return -1;
    }

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    tlv = reinterpret_cast<em_tlv_t *>(buff + header_len);
    tlv_len = static_cast<int>(len - header_len);

    while (tlv_len >= static_cast<int>(sizeof(em_tlv_t)) && tlv->type != em_tlv_type_eom) {
        unsigned int cur_tlv_len = ntohs(tlv->len);

        if (tlv_len < static_cast<int>(sizeof(em_tlv_t) + cur_tlv_len)) {
            em_printfout("%s:%d Truncated TLV in Channel Scan Request",__func__, __LINE__);
            return -1;
        }

        if (tlv->type == em_tlv_type_channel_scan_req) {

            unsigned char *payload = tlv->value;
            unsigned char *payload_end = payload + cur_tlv_len;

            /* Validate fixed request header */
            if (payload + sizeof(em_channel_scan_req_t) > payload_end) {
                em_printfout("%s:%d Invalid Channel Scan Request TLV",__func__, __LINE__);
                return -1;
            }

            req = reinterpret_cast<em_channel_scan_req_t *>(payload);

            memcpy(params.ruid, get_radio_interface_mac(), sizeof(mac_address_t));
            params.num_op_classes = req->num_op_classes;

            if (params.num_op_classes > EM_MAX_OP_CLASS) {
                em_printfout("%s:%d Invalid num_op_classes=%u", __func__, __LINE__, params.num_op_classes);
                return -1;
            }

            op_class = req->op_class;

            for (i = 0; i < params.num_op_classes; i++) {

                /* Validate fixed op-class entry */
                if (reinterpret_cast<unsigned char *>(op_class) + sizeof(em_channel_scan_req_op_class_t) > payload_end) {
                    em_printfout("%s:%d Truncated operating class entry", __func__, __LINE__);
                    return -1;
                }

                if (op_class->num_channels > EM_MAX_CHANNELS_IN_LIST) {
                    em_printfout("%s:%d Invalid num_channels=%u", __func__, __LINE__, op_class->num_channels);
                    return -1;
                }

                /* Validate variable-length channel list */
                if (reinterpret_cast<unsigned char *>(op_class) + sizeof(em_channel_scan_req_op_class_t) +
                                                                             op_class->num_channels > payload_end) {
                    em_printfout("%s:%d Truncated channel list", __func__, __LINE__);
                    return -1;
                }

                params.op_class[i].op_class = op_class->op_class;
                params.op_class[i].num_channels = op_class->num_channels;

                memcpy(params.op_class[i].channels, op_class->channel_list, op_class->num_channels);

                op_class = reinterpret_cast<em_channel_scan_req_op_class_t *>(reinterpret_cast<unsigned char *>(op_class) +
                                                 sizeof(em_channel_scan_req_op_class_t) + op_class->num_channels);
            }
        }

        tlv_len -= static_cast<int>(sizeof(em_tlv_t) + cur_tlv_len);

        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + cur_tlv_len);
    }

    if (params.num_op_classes > 0) {
        if (!m_last_scan_req) {
                m_last_scan_req = std::make_unique<em_scan_params_t>();
            }
            memcpy(m_last_scan_req.get(), &params, sizeof(em_scan_params_t));
        m_last_scan_req_valid = true;
            get_mgr()->io_process(em_bus_event_type_channel_scan_params,  reinterpret_cast<unsigned char *> (&params), sizeof(em_scan_params_t));
    } else {
        m_last_scan_req.reset();
        m_last_scan_req_valid = false;
    }
    send_1905_ack_message(ntohs(cmdu->id), ACK_FROM_AGENT);
    return 0;
}


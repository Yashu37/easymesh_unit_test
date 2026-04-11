#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"

int em_capability_t::process_single_tlv_in_1905_message(unsigned char *pkt_buff, unsigned int pkt_len, em_tlv_type_t tlv_type,
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

    em_tlv_t* tlvs_start = reinterpret_cast<em_tlv_t *>(pkt_buff + header_len);
    unsigned int tlvs_len = pkt_len - header_len;

    if (tlvs_len < sizeof(em_tlv_t)) {
            return -1;
    }

    if (tlvs_start->type == em_tlv_type_eom) {
            if (ntohs(tlvs_start->len) != 0) {
                    return -1;
            }

	    return 0;
    }

    tlv = em_msg_t::get_first_tlv(tlvs_start, tlvs_len);

    if (!tlv) {
            return -1;
    }

    while (tlv != NULL) {
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        if (tlv->type == tlv_type) {
            uint16_t tlv_len = ntohs(tlv->len);
            return (this->*handler)(tlv->value, tlv_len);
        }

        tlv = em_msg_t::get_next_tlv(tlv, tlvs_start, tlvs_len);
    }

    return 0;
}


#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"

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
/*

int em_metrics_t::process_tlv_bssid(
    unsigned char *buff,
    unsigned int len,
    em_tlv_type_t tlv_type,
    int (em_metrics_t::*handler)(unsigned char*, bssid_t)
)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    bssid_t bssid = {0};

    if (!buff || len <= sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) || !handler)
        return -1;

    tlv_start = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tmp_len > 0) && (tlv->type != em_tlv_type_eom)) {

        if (tmp_len < sizeof(em_tlv_t))
            break;

        unsigned int tlv_len = ntohs(tlv->len);

        if (tmp_len < sizeof(em_tlv_t) + tlv_len)
            break;

        if (tlv->type == tlv_type) {
            return (this->*handler)(tlv->value, bssid);
        }

        tmp_len -= sizeof(em_tlv_t) + tlv_len;
        tlv = reinterpret_cast<em_tlv_t*>(
            reinterpret_cast<unsigned char*>(tlv) + sizeof(em_tlv_t) + tlv_len);
    }

    return 0;
}

int em_metrics_t::process_tlv_data(
    unsigned char *buff,
    unsigned int len,
    em_tlv_type_t tlv_type,
    int (em_metrics_t::*handler)(unsigned char*)
)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;

    if (!buff || len <= sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) || !handler)
        return -1;

    tlv_start = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tmp_len > 0) && (tlv->type != em_tlv_type_eom)) {

        if (tmp_len < sizeof(em_tlv_t))
            break;

        unsigned int tlv_len = ntohs(tlv->len);

        if (tmp_len < sizeof(em_tlv_t) + tlv_len)
            break;

        if (tlv->type == tlv_type) {
            return (this->*handler)(tlv->value);
        }

        tmp_len -= sizeof(em_tlv_t) + tlv_len;
        tlv = reinterpret_cast<em_tlv_t*>(
            reinterpret_cast<unsigned char*>(tlv) + sizeof(em_tlv_t) + tlv_len);
    }

    return 0;
}

int em_metrics_t::process_tlv_data_len(
    unsigned char *buff,
    unsigned int len,
    em_tlv_type_t tlv_type,
    int (em_metrics_t::*handler)(unsigned char*, unsigned int)
)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;

    if (!buff || len <= sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) || !handler)
        return -1;

    tlv_start = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tmp_len > 0) && (tlv->type != em_tlv_type_eom)) {

        if (tmp_len < sizeof(em_tlv_t))
            break;

        unsigned int tlv_len = ntohs(tlv->len);

        if (tmp_len < sizeof(em_tlv_t) + tlv_len)
            break;

        if (tlv->type == tlv_type) {
            return (this->*handler)(tlv->value, tlv_len);
        }

        tmp_len -= sizeof(em_tlv_t) + tlv_len;
        tlv = reinterpret_cast<em_tlv_t*>(
            reinterpret_cast<unsigned char*>(tlv) + sizeof(em_tlv_t) + tlv_len);
    }

    return 0;
}
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>
#if 1
bool em_msg_t::get_supported_service(em_supported_service_t *svc)
{
    unsigned int tlv_len;
    if (!svc) {
        return false;
    }

    em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(m_buff);
    unsigned int len = m_len;
    while ((len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
        tlv_len = ntohs(tlv->len);
        if (len < sizeof(em_tlv_t) + tlv_len) {
            return false;
        }
        if (tlv->type == em_tlv_type_supported_service) {
             if (tlv_len < 2) {
                 return false;
            }
            unsigned int copy_len = tlv_len - 1;
            if (copy_len > EM_MAX_SERVICE) {
                copy_len = EM_MAX_SERVICE;
            }
            svc->num = tlv->value[0];
            if (svc->num > copy_len) {
                svc->num = static_cast<unsigned char>(copy_len);
            }
            memset(svc->service, 0, EM_MAX_SERVICE);
            memcpy(svc->service, &tlv->value[1], svc->num);
            return true;
        }
        len -= static_cast<unsigned int>(sizeof(em_tlv_t) + tlv_len);
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + tlv_len);
    }
    return false;
}
#endif
#if 0
bool em_msg_t::get_supported_service(em_supported_service_t *svc)
{
    unsigned int tlv_len;

    if (!svc || !m_buff) {  // FIX 1: Check output and input pointers
        return false;
    }

    // FIX 2: Explicitly define the TLV header length (Type + Length).
    constexpr unsigned int TLV_HEADER_LEN = 3;

    unsigned int len = m_len;
    unsigned char *buff = m_buff;

    while (len >= TLV_HEADER_LEN) {  // FIX 3: Validate complete TLV header
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(buff);

        if (tlv->type == em_tlv_type_eom) {
            return false;
        }

        tlv_len = ntohs(tlv->len);

        // FIX 4: Validate the TLV value against the remaining buffer.
        if (tlv_len > len - TLV_HEADER_LEN) {
            return false;
        }

        if (tlv->type == em_tlv_type_supported_service) {

            // FIX 5: The service count field must be present.
            if (tlv_len < 1) {
                return false;
            }

            unsigned int num_services = tlv->value[0];

            // FIX 6: Reject inconsistent service count and TLV length.
            if (tlv_len != 1U + num_services) {
                return false;
            }

            // FIX 7: Reject service counts exceeding destination capacity.
            if (num_services > EM_MAX_SERVICE) {
                return false;
            }

            // FIX 8: Update output only after all validation succeeds.
            memset(svc->service, 0, sizeof(svc->service));

            svc->num = static_cast<unsigned char>(num_services);

            if (num_services > 0) {
                memcpy(svc->service, &tlv->value[1], num_services);
            }

            return true;
        }

        // FIX 9: Advance safely to the next TLV.
        unsigned int total_len = TLV_HEADER_LEN + tlv_len;

        len -= total_len;
        buff += total_len;
    }

    return false;
}
#endif

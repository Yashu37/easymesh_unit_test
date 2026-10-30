#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>
#if 0
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
            // Check 4: SupportedService must contain the service-count field
            if (tlv_len < 1) {
                return false;
            }

            unsigned int copy_len = tlv_len - 1;

            if (copy_len > EM_MAX_SERVICE) {
                copy_len = EM_MAX_SERVICE;
            }

            svc->num = tlv->value[0];
#if 1
            // Check 5: Service count must match the TLV length
            if (tlv_len != 1U + svc->num) {
                return false;
            }
#endif
#if 1
            // Check 6: Destination capacity
            if (svc->num > EM_MAX_SERVICE) {
                return false;
            }
#endif
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

void em_msg_t::set_m1(unsigned char *tlvs, unsigned int len)
{
    m_buff = tlvs;
    m_len = len;
}

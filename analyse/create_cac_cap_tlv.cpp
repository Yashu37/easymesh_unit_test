/*
 * HANDLER: create_cac_cap_tlv
 *
 * Function copied verbatim from unified-wifi-mesh src/em/em.cpp (develop @ 1ba9529), em_t::create_cac_cap_tlv.
 * Local arrays: sys_cc[3], buf[8] (both used safely). The loops are bounded by cac_radio->cac_methods_num (unsigned char,
 * array of EM_MAX_CAC_METHODS = 4), method->op_classes_num (array of EM_MAX_OP_CLASS = 48) and op->num (channels[16]),
 * all taken from the data model without a clamp. The output buffer has no size parameter (caller: send_ap_cap_report_msg,
 * tlv->value inside a 16 KiB buffer). Scaffolding: dm with 3 radio slots, em_printfout is the harness logger.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_cac_cap_tlv.h"

namespace ccc {
#ifndef em_printfout
#endif
unsigned char out_store[CCC_OUT_LEFT + CCC_OUT_SZ + CCC_GUARD];
dm_easy_mesh_t *g_dm = NULL;
short g_len = 0;

/* --- copied verbatim from src/em/em.cpp --- */
short em_t::create_cac_cap_tlv(unsigned char *buff)
{
    unsigned char *tmp = buff;
    dm_easy_mesh_t *dm = get_data_model();

    // Country Code - 2 octets
    em_device_info_t *dev_info = dm->get_device_info();
    if (dev_info != NULL && dev_info->country_code[0] != '\0') {
        *tmp++ = static_cast<unsigned char>(dev_info->country_code[0]);
        *tmp++ = static_cast<unsigned char>(dev_info->country_code[1]);
    } else {
        /* Fallback: read the kernel regulatory country via 'iw reg get' */
        char sys_cc[3] = {0};//{'U', 'S', '\0'};
        FILE *fp = popen("iw reg get 2>/dev/null | awk '/^country/ {print substr($2,1,2); exit}'", "r");
        if (fp != NULL) {
            char buf[8] = {};
            if (fgets(buf, sizeof(buf), fp) != NULL && buf[0] >= 'A' && buf[0] <= 'Z') {
                sys_cc[0] = buf[0];
                sys_cc[1] = (buf[1] >= 'A' && buf[1] <= 'Z') ? buf[1] : 'S';
            }
            pclose(fp);
        }
        *tmp++ = static_cast<unsigned char>(sys_cc[0]);
        *tmp++ = static_cast<unsigned char>(sys_cc[1]);
    }

    /* Num_Radio placeholder — filled after we know how many radios have CAC */
    unsigned char *num_radio_ptr = tmp++;
    unsigned char cac_radio_count = 0;

    unsigned int max_radios = dm->get_num_radios();
    if (max_radios > EM_MAX_BANDS) max_radios = EM_MAX_BANDS;

    for (unsigned int index = 0; index < max_radios; index++) {
        if (dm->get_radio_by_ref(index).m_radio_info.band != em_freq_band_5) {
            continue;
        }
        dm_radio_cap_t *radio_cap = dm->get_radio_cap(index);
        if (radio_cap == NULL) {
            em_printfout("create_cac_cap_tlv: radio[%u] get_radio_cap returned NULL", index);
            continue;
        }
        em_radio_cap_info_t *cap_info = radio_cap->get_radio_cap_info();
        if (cap_info == NULL) {
            em_printfout("create_cac_cap_tlv: radio[%u] get_radio_cap_info returned NULL", index);
            continue;
        }
        em_cac_cap_radio_t *cac_radio = &cap_info->cac_cap;

        /* Only include radios that can perform CAC */
        if (cac_radio->cac_methods_num == 0) {
            em_printfout("create_cac_cap_tlv: radio[%u] cac_methods_num=0, skipping", index);
            continue;
        }

        /* RUID — 6 octets */
        memcpy(tmp, cac_radio->ruid, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);

        /* Num_Types — 1 octet */
        *tmp++ = cac_radio->cac_methods_num;

        for (unsigned char m = 0; m < cac_radio->cac_methods_num; m++) {
            em_cac_cap_method_t *method = &cac_radio->cac_methods[m];

            /* Method — 1 octet */
            *tmp++ = method->cac_method;

            /* Duration — 3 octets big-endian */
            unsigned int dur = method->cac_duration;
            *tmp++ = static_cast<unsigned char>((dur >> 16) & 0xff);
            *tmp++ = static_cast<unsigned char>((dur >>  8) & 0xff);
            *tmp++ = static_cast<unsigned char>( dur        & 0xff);

            /* Num_OpClass — 1 octet */
            *tmp++ = method->op_classes_num;

            for (unsigned char oc = 0; oc < method->op_classes_num; oc++) {
                em_cac_op_class_t *op = &method->op_classes[oc];

                /* OpClass — 1 octet */
                *tmp++ = op->op_class;

                /* Num_Chan — 1 octet */
                *tmp++ = op->num;

                /* Channel × Num_Chan */
                for (unsigned char ch = 0; ch < op->num; ch++) {
                    *tmp++ = op->channels[ch];
                }
            }
        }
        cac_radio_count++;
    }

    *num_radio_ptr = cac_radio_count;

    em_printfout("create_cac_cap_tlv: num_radios=%u CC='%c%c'",
        cac_radio_count,
        (dev_info && dev_info->country_code[0]) ? dev_info->country_code[0] : '?',
        (dev_info && dev_info->country_code[1]) ? dev_info->country_code[1] : '?');

    return static_cast<short>(tmp - buff);
}

void invoke(void)
{
    em_t em; em.m_dm = g_dm;
    g_len = em.create_cac_cap_tlv(out_store + CCC_OUT_LEFT);
}
} /* namespace ccc */

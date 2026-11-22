/*
 * HANDLER: dm_bss_t::encode (fixes 1-3 applied, start fix n / end fix n markers)
 *
 * Function copied verbatim from unified-wifi-mesh src/dm/dm_bss.cpp (develop @ 1ba9529), dm_bss_t::encode. Local arrays: mac_str[18], haul_type_str[64] (only assigned for the five known haul types), and the
 * variable-length array vendor_ies[2 * vendor_elements_len + 1]. Loops are bounded by the raw num_fronthaul_akms /
 * num_backhaul_akms (unsigned char, arrays of EM_MAX_AKMS = 10) and vendor_elements_len (array of 2310). Strings added with
 * cJSON_AddStringToObject: ssid (32 bytes), timestamp (128), est_svc_params_* (32), all without a guaranteed NUL.
 * The real cJSON library builds the output object.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dm_bss_encode.h"

namespace dbe {
dm_bss_t *g_bss = NULL; cJSON *g_obj = NULL;

/* --- copied verbatim from src/dm/dm_bss.cpp --- */
void dm_bss_t::encode(cJSON *obj, bool summary)
{
    mac_addr_str_t  mac_str;
    unsigned short i;
/* start fix 3 */
	em_short_string_t	haul_type_str = {0};
/* end fix 3 */

    dm_easy_mesh_t::macbytes_to_string(m_bss_info.bssid.mac, mac_str);
    cJSON_AddStringToObject(obj, "BSSID", mac_str);
    if (strcmp(util::mac_to_string(m_bss_info.mld_mac).c_str(), "00:00:00:00:00:00") != 0) {
        cJSON_AddStringToObject(obj, "MLDAddr", util::mac_to_string(m_bss_info.mld_mac).c_str());
    }

	//TBD: Currently using default hard-coded values of VLAN-ID, need to integrate so that DM is updated from DB/CLI/Agent
	switch (m_bss_info.id.haul_type) {
		case em_haul_type_fronthaul:
			strncpy(haul_type_str, "Fronthaul", strlen("Fronthaul") + 1);
			break;

		case em_haul_type_backhaul:
			strncpy(haul_type_str, "Backhaul", strlen("Backhaul") + 1);
			break;

		case em_haul_type_iot:
			strncpy(haul_type_str, "IoT", strlen("IoT") + 1);
			break;

		case em_haul_type_configurator:
			strncpy(haul_type_str, "Configurator", strlen("Configurator") + 1);
			break;

		case em_haul_type_hotspot:
			strncpy(haul_type_str, "Hotspot", strlen("Hotspot") + 1);
			break;

		default:
			break;
	}

    cJSON_AddStringToObject(obj, "HaulType", haul_type_str);
    cJSON_AddStringToObject(obj, "SSID", m_bss_info.ssid);
    cJSON_AddBoolToObject(obj, "Enabled", m_bss_info.enabled);
    cJSON_AddStringToObject(obj, "TimeStamp", m_bss_info.timestamp);
    cJSON_AddNumberToObject(obj, "VapMode", m_bss_info.vap_mode);
    
	if (summary == true) {
        return;
    }

    cJSON_AddNumberToObject(obj, "LastChange", m_bss_info.last_change);
    cJSON_AddNumberToObject(obj, "UnicastBytesSent", m_bss_info.unicast_bytes_sent);
    cJSON_AddNumberToObject(obj, "UnicastBytesReceived", m_bss_info.unicast_bytes_rcvd);
    cJSON_AddNumberToObject(obj, "NumberOfSTA", m_bss_info.numberofsta );
    cJSON_AddStringToObject(obj, "EstServiceParametersBE", m_bss_info.est_svc_params_be);
    cJSON_AddStringToObject(obj, "EstServiceParametersBK", m_bss_info.est_svc_params_bk);
    cJSON_AddStringToObject(obj, "EstServiceParametersVI", m_bss_info.est_svc_params_vi);
    cJSON_AddStringToObject(obj, "EstServiceParametersVO", m_bss_info.est_svc_params_vo);
    cJSON_AddNumberToObject(obj, "ByteCounterUnits", m_bss_info.byte_counter_units);
    cJSON_AddBoolToObject(obj, "Profile1bSTAsDisallowed",  m_bss_info.profile_1b_sta_allowed);
    cJSON_AddBoolToObject(obj, "Profile2bSTAsDisallowed",  m_bss_info.profile_2b_sta_allowed);
    cJSON_AddNumberToObject(obj, "AssociationAllowanceStatus", m_bss_info.assoc_allowed_status);
    cJSON_AddBoolToObject(obj, "FronthaulUse", m_bss_info.fronthaul_use);
    cJSON_AddBoolToObject(obj, "BackhaulUse", m_bss_info.backhaul_use);
    cJSON_AddBoolToObject(obj, "R1disallowed", m_bss_info.r1_disallowed);
    cJSON_AddBoolToObject(obj, "R2disallowed", m_bss_info.r2_disallowed);
    cJSON_AddBoolToObject(obj, "MultiBSSID", m_bss_info.multi_bssid);
    cJSON_AddBoolToObject(obj, "TransmittedBSSID", m_bss_info.transmitted_bssid);

    cJSON *fronthaul_akmsArray = cJSON_CreateArray();
/* start fix 1 */
    unsigned int num_fronthaul_akms = m_bss_info.num_fronthaul_akms > EM_MAX_AKMS ? EM_MAX_AKMS : m_bss_info.num_fronthaul_akms;
    unsigned int num_backhaul_akms = m_bss_info.num_backhaul_akms > EM_MAX_AKMS ? EM_MAX_AKMS : m_bss_info.num_backhaul_akms;
/* end fix 1 */
/* start fix 1 */
    for (i = 0; i < num_fronthaul_akms; i++) {
/* end fix 1 */
        cJSON_AddItemToArray(fronthaul_akmsArray, cJSON_CreateString(m_bss_info.fronthaul_akm[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "FronthaulAKMsAllowed", fronthaul_akmsArray);

    cJSON *backhaul_akmsArray = cJSON_CreateArray();
/* start fix 1 */
    for (i = 0; i < num_backhaul_akms; i++) {
/* end fix 1 */
        cJSON_AddItemToArray(backhaul_akmsArray, cJSON_CreateString(m_bss_info.backhaul_akm[i]));
    }

    // Add the array to the object
    cJSON_AddItemToObject(obj, "BackhaulAKMsAllowed", backhaul_akmsArray);

    // Add vendor elements (ExtraVendorIEs) as hex string
/* start fix 2 */
    size_t vendor_elements_len = m_bss_info.vendor_elements_len > sizeof(m_bss_info.vendor_elements) ? sizeof(m_bss_info.vendor_elements) : m_bss_info.vendor_elements_len;
/* end fix 2 */
/* start fix 2 */
    char vendor_ies[2 * vendor_elements_len + 1] = {0};
    if (vendor_elements_len > 0) {
/* end fix 2 */
        memset(vendor_ies, 0, sizeof(vendor_ies));
/* start fix 2 */
        for (unsigned int i = 0; i < vendor_elements_len; i++) {
/* end fix 2 */
            unsigned int offset = i * 2;
            snprintf(vendor_ies + offset, sizeof(vendor_ies) - offset, "%02x", m_bss_info.vendor_elements[i]);
        }
    }
    cJSON_AddStringToObject(obj, "ExtraVendorIEs", vendor_ies);

}

/* writes 'A' over the stack below the caller so an unassigned haul_type_str holds known (non-NUL) garbage */
__attribute__((noinline)) void dirty_stack(void)
{
    volatile unsigned char junk[4096];
    for (size_t i = 0; i < sizeof(junk); i++) junk[i] = 'A';
}

void invoke(const test_case_t *tc)
{
    dirty_stack();
    g_bss->encode(g_obj, tc->summary);
}
} /* namespace dbe */

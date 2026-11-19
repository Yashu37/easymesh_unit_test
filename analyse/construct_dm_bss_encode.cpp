/*
 * TEST CASES / CONSTRUCTOR: construct_dm_bss_encode
 *
 * dm_bss_t lives on the heap with before_info[] / after_info[] (members around m_bss_info, poisoned by the runner).
 * Variant 0 = BSS bssid 02:00:00:00:10:01, SSID "mesh", haul fronthaul, timestamp "ts", 2 fronthaul AKMs (sae, psk), 1 backhaul
 * AKM (psk), 4 vendor bytes de:ad:be:ef. Other variants:
 *   1..4 haul backhaul / iot / configurator / hotspot       5 unknown haul type (em_haul_type_max): haul_type_str is never assigned
 *   6 vendor_elements_len 0        7 len 1        8 len 2310 (largest valid)        9 mld_mac set        10 10 AKMs each (largest valid)
 *   11 no AKMs     12 num_fronthaul_akms 255     14 num_backhaul_akms 255
 *   16 vendor_elements_len 3000    17 vendor_elements_len 10000000 (the stack array vendor_ies needs 20 MB)
 *   18 ssid of 32 'S' (no NUL: the string read continues into the 'enabled' member, inside the object, so only the output is wrong)
 * Not modelled as cases because they stay inside the object (no ASan report, no visible effect here): num_backhaul_akms 11..46,
 * vendor_elements_len 2311, timestamp / est_svc_params without NUL, an unknown haul type (haul_type_str unassigned, reads stack garbage).
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan report;
 * FORK_CRASH=1 forks each one. expect_haul / expect_ssid / expect_fh / expect_bh / expect_vendor_len (characters) / expect_mld.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dm_bss_encode.h"

namespace dbe {
/* {name, variant, summary, haul, ssid, fh, bh, vendor_len, mld, crash} */
test_case_t suite[] = {
 {"ok_normal",                         0, false, "Fronthaul", "mesh", 2, 1, 8, 0, false},
 {"ok_summary_only_short_form",        0, true,  "Fronthaul", "mesh", -1, -1, -1, 0, false},
 {"ok_haul_backhaul",                  1, false, "Backhaul", "mesh", 2, 1, 8, 0, false},
 {"ok_haul_iot",                       2, false, "IoT", "mesh", 2, 1, 8, 0, false},
 {"ok_haul_configurator",              3, false, "Configurator", "mesh", 2, 1, 8, 0, false},
 {"ok_haul_hotspot",                   4, false, "Hotspot", "mesh", 2, 1, 8, 0, false},
 {"ok_vendor_len_0_empty_string",      6, false, NULL, NULL, -1, -1, 0, -1, false},
 {"ok_vendor_len_1",                   7, false, NULL, NULL, -1, -1, 2, -1, false},
 {"ok_vendor_len_2310_largest_valid",  8, false, NULL, NULL, -1, -1, 4620, -1, false},
 {"ok_mld_mac_present",                9, false, NULL, NULL, -1, -1, -1, 1, false},
 {"ok_mld_mac_absent",                 0, false, NULL, NULL, -1, -1, -1, 0, false},
 {"ok_10_akms_each_largest_valid",    10, false, NULL, NULL, 10, 10, -1, -1, false},
 {"ok_no_akms",                       11, false, NULL, NULL, 0, 0, -1, -1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_ssid_32_chars_no_nul_must_not_read_on [spec]", 18, false, NULL, "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS", -1, -1, -1, -1, false},
 /* ---- CRASH cases on the original handler: run last, unforked ---- */
 {"crash_num_fronthaul_akms_255",     12, false, NULL, NULL, 10, 1, -1, -1, true},
 {"crash_num_backhaul_akms_255",      14, false, NULL, NULL, 2, 10, -1, -1, true},
 {"crash_vendor_len_3000",            16, false, NULL, NULL, -1, -1, 4620, -1, true},
 {"crash_vendor_len_10000000_stack",  17, false, NULL, NULL, -1, -1, 4620, -1, true},
 {NULL, 0, false, NULL, NULL, 0, 0, 0, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_bss = new dm_bss_t; memset((void *)g_bss, 0, sizeof(*g_bss));
    em_bss_info_t *b = &g_bss->m_bss_info; int v = tc->variant;
    unsigned char m[6] = {2, 0, 0, 0, 0x10, 0x01}; memcpy(b->bssid.mac, m, 6);
    snprintf(b->ssid, sizeof(b->ssid), "mesh"); snprintf(b->timestamp, sizeof(b->timestamp), "ts");
    b->id.haul_type = em_haul_type_fronthaul; b->enabled = true;
    b->num_fronthaul_akms = 2; snprintf(b->fronthaul_akm[0], 64, "sae"); snprintf(b->fronthaul_akm[1], 64, "psk");
    b->num_backhaul_akms = 1; snprintf(b->backhaul_akm[0], 64, "psk");
    unsigned char ie[4] = {0xde, 0xad, 0xbe, 0xef}; memcpy(b->vendor_elements, ie, 4); b->vendor_elements_len = 4;
    switch (v) {
    case 1: b->id.haul_type = em_haul_type_backhaul; break;
    case 2: b->id.haul_type = em_haul_type_iot; break;
    case 3: b->id.haul_type = em_haul_type_configurator; break;
    case 4: b->id.haul_type = em_haul_type_hotspot; break;
    case 5: b->id.haul_type = em_haul_type_max; break;
    case 6: b->vendor_elements_len = 0; break;
    case 7: b->vendor_elements_len = 1; break;
    case 8: memset(b->vendor_elements, 0xab, sizeof(b->vendor_elements)); b->vendor_elements_len = WIFI_AP_MAX_VENDOR_IE_LEN; break;
    case 9: { unsigned char ml[6] = {2, 0, 0, 0, 0x20, 0x01}; memcpy(b->mld_mac, ml, 6); } break;
    case 10: for (int i = 0; i < EM_MAX_AKMS; i++) { snprintf(b->fronthaul_akm[i], 64, "fh%d", i); snprintf(b->backhaul_akm[i], 64, "bh%d", i); }
             b->num_fronthaul_akms = 10; b->num_backhaul_akms = 10; break;
    case 11: b->num_fronthaul_akms = 0; b->num_backhaul_akms = 0; break;
    case 12: b->num_fronthaul_akms = 255; break;
    case 13: b->num_backhaul_akms = 11; break;
    case 14: b->num_backhaul_akms = 255; break;
    case 15: b->vendor_elements_len = 2311; break;
    case 16: b->vendor_elements_len = 3000; break;
    case 17: b->vendor_elements_len = 10000000; break;
    case 18: memset(b->ssid, 'S', sizeof(b->ssid)); break;
    case 19: memset(b->timestamp, 'T', sizeof(b->timestamp)); break;
    case 20: memset(b->est_svc_params_be, 'E', sizeof(b->est_svc_params_be)); break;
    default: break;
    }
    g_obj = cJSON_CreateObject();
}
void teardown(void) { cJSON_Delete(g_obj); g_obj = NULL; delete g_bss; g_bss = NULL; }
} /* namespace dbe */

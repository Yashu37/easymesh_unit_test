/*
 * TEST CASES / CONSTRUCTOR: construct_create_cac_cap_tlv
 *
 * Output goes to out_store + CCC_OUT_LEFT (CCC_OUT_SZ bytes; the runner poisons the bytes in front and CCC_GUARD bytes
 * behind). The data model has up to 3 radio slots; each radio's em_radio_cap_info_t has before_cac[] / after_cac[] around
 * cac_cap (poisoned by the runner), so reading cac_methods[4], op_classes[48] or channels[16] of the LAST entry lands in poison.
 * Radio i has ruid 02:00:00:00:00:1(i+1). Variants:
 *   0 band-5 radios with cac_methods_num 0 (skipped)
 *   1 radio0 2.4 GHz with 1 method (skipped), radio1 5 GHz: 1 method (CAC 0, duration 0x010203, op class 115 with channels 36, 40); radio1 ruid = 02:00:00:00:00:12
 *   2 radio0 5 GHz: 2 methods, method0 op classes (115: 36, 40, 44) and (118: all channels, num 0), method1 none
 *   3 every radio 5 GHz, 1 method without op classes
 *   4 radio0 largest valid: 4 methods x 48 op classes x 16 channels
 *   5 radio0 cac_methods_num 5       6 radio0 cac_methods_num 255      11 radio1 cac_methods_num 5
 *   7 radio0 4 methods, method3 op_classes_num 49   8 same with 255
 *   9 radio0 4 methods, method3 op_classes_num 48, last op class num 17   10 same with num 255
 * The clamp_* cases read past the arrays and ABORTED on the original handler; fixes 1-3 clamp the three counts (and the
 * counts written into the TLV) to 4 methods / 48 op classes / 16 channels. expect_hex = first bytes of the output (CC, radio count, ...).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_cac_cap_tlv.h"

namespace ccc {
/* {name, country, n_radios, variant, expect_len, expect_hex, crash} */
test_case_t suite[] = {
 {"ok_no_radios",                       "US", 0, 0, 3, "555300", false},
 {"ok_radios_without_cac_skipped",      "US", 3, 0, 3, "555300", false},
 {"ok_one_method_one_opclass",          "US", 2, 1, 3 + 6+1 + 1+3+1 + 2+2, "5553010200000000120100010203017302" "2428", false},
 {"ok_two_methods_with_opclasses",      "DE", 1, 2, 3 + 6+1 + (1+3+1 + (2+3) + (2+0)) + (1+3+1), "444501020000000011" "02" "02" "000000" "02" "73" "03" "24282c" "7600" "0000000000", false},
 {"ok_three_radios_one_method_each",    "US", 3, 3, 3 + 3 * (6+1 + 1+3+1), "555303", false},
 {"ok_two_radios_count_is_2",           "JP", 3, 3, 3 + 3 * 12, "4a50" "03", false},
 {"ok_largest_valid_4x48x16",           "US", 1, 4, 3 + 6+1 + 4 * (1+3+1 + 48 * (2+16)), "555301", false},
 {"ok_country_empty_uses_iw_fallback",  "",   0, 0, 3, NULL, false},
 {"ok_no_device_info_uses_iw_fallback", NULL, 0, 0, 3, NULL, false},
 {"ok_one_letter_country",              "U",  0, 0, 3, "5500", false},
 /* ---- were CRASH cases on the original handler (counts now clamped to the array sizes) ---- */
 {"clamp_cac_methods_num_5",            "US", 1, 5,  3 + 6+1 + 4 * 5,                          NULL, false},
 {"clamp_cac_methods_num_255",          "US", 1, 6,  3 + 6+1 + 4 * 5,                          NULL, false},
 {"clamp_radio1_cac_methods_num_5",     "US", 2, 11, 3 + (6+1+5) + (6+1 + 4 * 5),             NULL, false},
 {"clamp_op_classes_num_49",            "US", 1, 7,  3 + 6+1 + 3 * 5 + 5 + 48 * 2,             NULL, false},
 {"clamp_op_classes_num_255",           "US", 1, 8,  3 + 6+1 + 3 * 5 + 5 + 48 * 2,             NULL, false},
 {"clamp_channels_num_17",              "US", 1, 9,  3 + 6+1 + 3 * 5 + 5 + 47 * 2 + (2+16),    NULL, false},
 {"clamp_channels_num_255",             "US", 1, 10, 3 + 6+1 + 3 * 5 + 5 + 47 * 2 + (2+16),    NULL, false},
 {NULL, NULL, 0, 0, 0, NULL, false}
};

static void set_ruid(dm_easy_mesh_t *dm, int i) { unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(0x10 + i + 1)}; memcpy(dm->m_radio_cap[i].info.cac_cap.ruid, m, 6); }

void construct_input(const test_case_t *tc)
{
    memset(out_store, 0, sizeof(out_store));
    g_dm = new dm_easy_mesh_t;
    memset((void *)g_dm, 0, sizeof(*g_dm));
    g_dm->m_num_radios = tc->n_radios;
    g_dm->has_dev_info = tc->country != NULL;
    if (tc->country) snprintf(g_dm->dev_info.country_code, sizeof(g_dm->dev_info.country_code), "%s", tc->country);
    for (int i = 0; i < EM_MAX_BANDS; i++) { g_dm->m_radio[i].m_radio_info.band = em_freq_band_5; set_ruid(g_dm, i); }
    em_cac_cap_radio_t *r0 = &g_dm->m_radio_cap[0].info.cac_cap, *r1 = &g_dm->m_radio_cap[1].info.cac_cap;
    switch (tc->variant) {
    case 1:
        g_dm->m_radio[0].m_radio_info.band = em_freq_band_24; r0->cac_methods_num = 1;
        r1->cac_methods_num = 1; r1->cac_methods[0].cac_method = 0; r1->cac_methods[0].cac_duration = 0x010203;
        r1->cac_methods[0].op_classes_num = 1; r1->cac_methods[0].op_classes[0].op_class = 115; r1->cac_methods[0].op_classes[0].num = 2;
        r1->cac_methods[0].op_classes[0].channels[0] = 36; r1->cac_methods[0].op_classes[0].channels[1] = 40;
        break;
    case 2:
        r0->cac_methods_num = 2; r0->cac_methods[0].cac_method = 2; r0->cac_methods[0].cac_duration = 0x000000;
        r0->cac_methods[0].op_classes_num = 2;
        r0->cac_methods[0].op_classes[0].op_class = 115; r0->cac_methods[0].op_classes[0].num = 3;
        r0->cac_methods[0].op_classes[0].channels[0] = 36; r0->cac_methods[0].op_classes[0].channels[1] = 40; r0->cac_methods[0].op_classes[0].channels[2] = 44;
        r0->cac_methods[0].op_classes[1].op_class = 118; r0->cac_methods[0].op_classes[1].num = 0;
        r0->cac_methods[1].cac_method = 0;
        break;
    case 3:
        for (int i = 0; i < EM_MAX_BANDS; i++) g_dm->m_radio_cap[i].info.cac_cap.cac_methods_num = 1;
        break;
    case 4:
        r0->cac_methods_num = 4;
        for (int m = 0; m < 4; m++) { r0->cac_methods[m].op_classes_num = 48;
            for (int o = 0; o < 48; o++) { r0->cac_methods[m].op_classes[o].op_class = (unsigned char)(81 + o); r0->cac_methods[m].op_classes[o].num = 16; } }
        break;
    case 5:  r0->cac_methods_num = 5; break;
    case 6:  r0->cac_methods_num = 255; break;
    case 11: r0->cac_methods_num = 1; r1->cac_methods_num = 5; break;
    case 7:  r0->cac_methods_num = 4; r0->cac_methods[3].op_classes_num = 49; break;
    case 8:  r0->cac_methods_num = 4; r0->cac_methods[3].op_classes_num = 255; break;
    case 9:  r0->cac_methods_num = 4; r0->cac_methods[3].op_classes_num = 48; r0->cac_methods[3].op_classes[47].num = 17; break;
    case 10: r0->cac_methods_num = 4; r0->cac_methods[3].op_classes_num = 48; r0->cac_methods[3].op_classes[47].num = 255; break;
    default: break;
    }
}
void teardown(void) { delete g_dm; g_dm = NULL; }
} /* namespace ccc */

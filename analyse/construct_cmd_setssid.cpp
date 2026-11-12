/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_setssid
 *
 * Each case lists the input properties (SSID, AddRemoveChange, PassPhrase, Band,
 * HaulType, AKMsAllowed). String values go into val_buf[i] (runner poisons past
 * raw_data_len); the configuration JSON that get_config() returns is copied into
 * the runner-owned cfg_store (runner poisons past its NUL):
 *   0 = one entry {"SSID":"Home","PassPhrase":"homepass","Band":["5"],"HaulType":["Fronthaul"],
 *       "AKMsAllowed":["psk"],"AuthType":"WPA2 Personal"}
 *   1 = empty list          2 = one entry with only "SSID"     3 = not JSON
 *   4 = no NetworkSSIDList  5 = NetworkSSIDList is not an array 6 = top level is an array
 *   7 = ~4000 byte list (an Add pushes the output past EM_IO_BUFF_SZ)   8 = empty string
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input).
 * Cases marked [spec] are inputs a strict handler should reject / apply
 * (over-long values silently truncated, a Change that silently drops a field).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace css {

ccs::bus_data_prop_t props_buf[8];
alignas(16) char val_buf[8][CSS_VAL_SZ + CSS_PAD];
alignas(16) char cfg_store[CSS_CFG_SZ + CSS_PAD];
int num_props = 0;

#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define SS(v) S("SSID", v)
#define AR(v) S("AddRemoveChange", v)
#define PW(v) S("PassPhrase", v)
#define BD(v) S("Band", v)
#define HT(v) S("HaulType", v)
#define AK(v) S("AKMsAllowed", v)

test_case_t suite[] = {
 /* ---- Add ---- */
 {"ok_add_all_fields", 0, false, false, false, {SS("NewNet"), AR("Add"), PW("newpass123"), BD("5"), HT("Backhaul"), AK("sae"), E0}, 0,
  "{\"SSID\":\"NewNet\",\"PassPhrase\":\"newpass123\",\"Band\":[\"5\"],\"HaulType\":[\"Backhaul\"],\"AKMsAllowed\":[\"sae\"],\"AuthType\":\"WPA3 Personal\"}", NULL},
 {"ok_add_ssid_only", 0, false, false, false, {SS("Only"), AR("Add"), E0}, 0, "{\"SSID\":\"Only\"}", NULL},
 {"ok_add_to_empty_list", 1, false, false, false, {SS("First"), AR("Add"), PW("pw123456")}, 0, "\"NetworkSSIDList\":[{\"SSID\":\"First\",\"PassPhrase\":\"pw123456\"}]", NULL},
 {"ok_add_akms_psk", 0, false, false, false, {SS("A"), AR("Add"), AK("psk"), E0}, 0, "\"AKMsAllowed\":[\"psk\"],\"AuthType\":\"WPA2 Personal\"", NULL},
 {"ok_add_akms_psk_sae", 0, false, false, false, {SS("A"), AR("Add"), AK("psk+sae"), E0}, 0, "\"AuthType\":\"WPA3 Transition\"", NULL},
 {"ok_add_akms_open_empty", 0, false, false, false, {SS("A"), AR("Add"), AK(""), E0}, 0, "\"AKMsAllowed\":[],\"AuthType\":\"Open\"", NULL},
 {"ok_add_akms_spaces", 0, false, false, false, {SS("A"), AR("Add"), AK(" psk "), E0}, 0, "\"AKMsAllowed\":[\"psk\"]", NULL},
 {"ok_add_unknown_prop_ignored", 0, false, false, false, {SS("A"), AR("Add"), S("Foo", "bar"), E0}, 0, "{\"SSID\":\"A\"}", "bar"},
 {"ok_add_ssid_quote", 0, false, false, false, {SS("a\"b"), AR("Add"), E0}, 0, "\"SSID\":\"a\\\"b\"", NULL},
 {"ok_add_output_null", 0, false, true, false, {SS("A"), AR("Add"), E0}, 0, "{\"SSID\":\"A\"}", NULL},
 {"ok_add_existing_ssid_changes", 0, false, false, false, {SS("Home"), AR("Add"), PW("again123"), E0}, 0, "\"PassPhrase\":\"again123\"", "homepass"},
 /* ---- boundary lengths ---- */
 {"ok_ssid_32_chars", 0, false, false, false, {R("SSID", "S", 32), AR("Add"), E0}, 0, "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\"", NULL},
 {"ok_pass_63_chars", 0, false, false, false, {SS("A"), AR("Add"), R("PassPhrase", "P", 63), E0}, 0, "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\"", NULL},
 {"ok_band_16_chars", 0, false, false, false, {SS("A"), AR("Add"), R("Band", "B", 16), E0}, 0, "BBBBBBBBBBBBBBBB\"", NULL},
 {"rej_addremove_17_chars", 0, false, false, false, {SS("A"), R("AddRemoveChange", "A", 17), E0}, 2, NULL, NULL},
 {"rej_haul_33_chars", 0, false, false, false, {SS("A"), AR("Add"), R("HaulType", "H", 33), E0}, 2, NULL, NULL},
 {"rej_akms_32_chars", 0, false, false, false, {SS("A"), AR("Add"), R("AKMsAllowed", "K", 32), E0}, 2, NULL, NULL},
 /* ---- Change / Remove ---- */
 {"ok_change_pass_by_ssid", 0, false, false, false, {SS("Home"), AR("Change"), PW("changed99"), E0}, 0, "\"PassPhrase\":\"changed99\"", "homepass"},
 {"ok_change_by_haul", 0, false, false, false, {SS("Renamed"), AR("Change"), HT("Fronthaul"), E0}, 0, "\"SSID\":\"Renamed\"", "\"SSID\":\"Home\""},
 {"ok_change_band_akms", 0, false, false, false, {SS("Home"), AR("Change"), BD("6"), AK("sae"), E0}, 0, "\"Band\":[\"6\"]", "\"Band\":[\"5\"]"},
 {"ok_change_akms_open", 0, false, false, false, {SS("Home"), AR("Change"), AK(""), E0}, 0, "\"AuthType\":\"Open\"", "WPA2 Personal"},
 {"ok_remove_by_ssid", 0, false, false, false, {SS("Home"), AR("Remove"), E0}, 0, "\"NetworkSSIDList\":[]", "Home"},
 {"rej_remove_missing", 0, false, false, false, {SS("Ghost"), AR("Remove"), E0}, 2, NULL, NULL},
 {"rej_change_missing_ssid", 0, false, false, false, {SS("Ghost"), AR("Change"), PW("pw123456"), E0}, 2, NULL, NULL},
 {"rej_change_haul_no_match", 0, false, false, false, {SS("Home"), AR("Change"), HT("Backhaul"), E0}, 2, NULL, NULL},
 /* ---- entry without the key being changed: ReplaceItemInObject fails, new item is dropped ---- */
 {"ok_change_missing_pass_key [spec]", 2, false, false, false, {SS("Home"), AR("Change"), PW("newpw1234"), E0}, 0, "\"PassPhrase\":\"newpw1234\"", NULL},
 {"ok_change_missing_band_key [spec]", 2, false, false, false, {SS("Home"), AR("Change"), BD("6"), E0}, 0, "\"Band\":[\"6\"]", NULL},
 {"ok_change_missing_akms_key [spec]", 2, false, false, false, {SS("Home"), AR("Change"), AK("psk"), E0}, 0, "\"AKMsAllowed\":[\"psk\"]", NULL},
 /* ---- [spec]: over-long values silently truncated ---- */
 {"rej_ssid_33_chars [spec]", 0, false, false, false, {R("SSID", "S", 33), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_pass_64_chars [spec]", 0, false, false, false, {SS("A"), AR("Add"), R("PassPhrase", "P", 64), E0}, 2, NULL, NULL},
 {"rej_band_17_chars [spec]", 0, false, false, false, {SS("A"), AR("Add"), R("Band", "B", 17), E0}, 2, NULL, NULL},
 /* ---- rejected input ---- */
 {"rej_no_props", 0, true, false, false, {E0}, 2, NULL, NULL},
 {"rej_missing_ssid", 0, false, false, false, {AR("Add"), E0}, 2, NULL, NULL},
 {"rej_missing_addremove", 0, false, false, false, {SS("A"), E0}, 2, NULL, NULL},
 {"rej_ssid_empty", 0, false, false, false, {SS(""), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_ssid_int_type", 0, false, false, false, {I32("SSID", 5), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_addremove_lowercase", 0, false, false, false, {SS("A"), AR("add"), E0}, 2, NULL, NULL},
 {"rej_addremove_unknown", 0, false, false, false, {SS("A"), AR("Update"), E0}, 2, NULL, NULL},
 {"rej_haul_both", 0, false, false, false, {SS("A"), AR("Add"), HT("Fronthaul,Backhaul"), E0}, 2, NULL, NULL},
 {"rej_haul_invalid", 0, false, false, false, {SS("A"), AR("Add"), HT("Mesh"), E0}, 2, NULL, NULL},
 {"rej_akms_invalid", 0, false, false, false, {SS("A"), AR("Add"), AK("wpa2"), E0}, 2, NULL, NULL},
 {"rej_akms_comma", 0, false, false, false, {SS("A"), AR("Add"), AK("psk,sae"), E0}, 2, NULL, NULL},
 {"rej_akms_int_type", 0, false, false, false, {SS("A"), AR("Add"), I32("AKMsAllowed", 1), E0}, 2, NULL, NULL},
 /* ---- bad configuration / controller ---- */
 {"rej_cfg_not_json", 3, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_cfg_empty_string", 8, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_cfg_no_list", 4, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_cfg_list_not_array", 5, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_cfg_top_level_array", 6, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_output_too_big", 7, false, false, false, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},
 {"rej_ctrl_missing", 0, false, false, true, {SS("A"), AR("Add"), E0}, 2, NULL, NULL},

 { NULL, 0, false, false, false, {E0}, 0, NULL, NULL }  /* sentinel */
};

static void add_prop(const char *name, int kind, const char *s, int i, int len)
{
    ccs::bus_data_prop_t *p = &props_buf[num_props];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->name_len = (uint32_t)strlen(p->name);
    if (kind == 0 || kind == 5) {
        char *v = val_buf[num_props];
        memset(v, 0, CSS_VAL_SZ + CSS_PAD);
        size_t n;
        if (kind == 5) { memset(v, s[0], (size_t)len); n = (size_t)len + 1; }
        else { n = strlen(s) + 1; memcpy(v, s, n); }
        p->value.data_type = ccs::bus_data_type_string;
        p->value.raw_data.bytes = v;
        p->value.raw_data_len = (unsigned int)n;
    } else {
        p->value.data_type = ccs::bus_data_type_int32;
        p->value.raw_data.i32 = i;
    }
    if (num_props > 0) props_buf[num_props - 1].next_data = p;
    num_props++;
}

void construct_input(const test_case_t *tc)
{
    static const char *cfgs[] = {
        "{\"NetworkSSIDList\":[{\"SSID\":\"Home\",\"PassPhrase\":\"homepass\",\"Band\":[\"5\"],\"HaulType\":[\"Fronthaul\"],\"AKMsAllowed\":[\"psk\"],\"AuthType\":\"WPA2 Personal\"}]}",
        "{\"NetworkSSIDList\":[]}",
        "{\"NetworkSSIDList\":[{\"SSID\":\"Home\"}]}",
        "this is not json",
        "{\"Other\":1}",
        "{\"NetworkSSIDList\":5}",
        "[1,2]",
        NULL,
        "",
    };
    memset(cfg_store, 0, sizeof(cfg_store));
    if (tc->cfg == 7) {
        int off = snprintf(cfg_store, CSS_CFG_SZ, "{\"NetworkSSIDList\":[");
        for (int k = 0; off < 4040; k++) off += snprintf(cfg_store + off, CSS_CFG_SZ - off, "{\"SSID\":\"n%04d\"},", k);
        snprintf(cfg_store + off, CSS_CFG_SZ - off, "{\"SSID\":\"z\"}]}");
    } else {
        snprintf(cfg_store, CSS_CFG_SZ, "%s", cfgs[tc->cfg]);
    }
    cfg_json = cfg_store;
    set_ctrl(!tc->ctrl_null);
    num_props = 0;
    for (int i = 0; tc->props[i].name != NULL; i++)
        add_prop(tc->props[i].name, tc->props[i].kind, tc->props[i].s, tc->props[i].i, tc->props[i].len);
}

} /* namespace css */

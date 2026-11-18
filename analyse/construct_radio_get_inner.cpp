/*
 * TEST CASES / CONSTRUCTOR: construct_radio_get_inner
 *
 * event_name lives in name_store at offset RGI_LEFT (runner poisons the bytes in front of it and
 * past its NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with radios r = 1..3:
 *   RUID 02:00:00:00:00:r, enabled = (r != 2), noise -(89+r), utilization 50+r, transmit 10+r,
 *   receive_self 20+r, receive_other 30+r, chip_vendor "Acme<r>", number_of_bss 2*r, radio_temp 40+r
 * and this op class list (m_num_opclass = 6):
 *   [0] radio 1 current  [1] radio 1 current  [2] radio 1 capability
 *   [3] radio 2 current  [4] radio 3 capability  [5] (empty entry, type none)
 * so CurrentOperatingClassProfileNumberOfEntries is 2 / 1 / 0 for radio 1 / 2 / 3.
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. Cases marked [spec] are wrong
 * behaviour (an instance like "1abc" is read as 1 by atoi). Cases named crash_* ABORT on the
 * original handler: method name shorter than the Network prefix, path that stops before the Device
 * / Radio instance (get_table_instance(NULL)), Radio instance 0 / 4 / alias / -1 / 1000000
 * (dm->m_radio[radio_instance - 1]), a chip_vendor without NUL (strlen runs past the 128 bytes) and
 * m_num_opclass 100 (loop runs past m_op_class[64]). A case flagged crash=true would run last and
 * UNFORKED (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radio_get_inner.h"

namespace rgi {

alignas(16) char name_store[RGI_LEFT + RGI_NAME_SZ + RGI_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(rad, p) N "Device.1.Radio." rad "." p
/* {name, event, no_pdata, no_dm, expect_rc, expect_val, variant, crash} */
#define OKV(n, rad, p, v) {n, EV(rad, p), false, false, 0, v, 0, false}
#define RJ(n, ev) {n, ev, false, false, 2, NULL, 0, false}
#define CR(n, ev) {n, ev, false, false, 2, NULL, 0, false}

test_case_t suite[] = {
 /* ---- every parameter name ---- */
 OKV("ok_id_radio1", "1", "ID", "AgAAAAAB"),
 OKV("ok_id_radio2", "2", "ID", "AgAAAAAC"),
 OKV("ok_id_radio3", "3", "ID", "AgAAAAAD"),
 OKV("ok_enabled_radio1", "1", "Enabled", "1"),
 OKV("ok_enabled_radio2", "2", "Enabled", "0"),
 OKV("ok_noise_radio1", "1", "Noise", "4294967206"),
 OKV("ok_noise_radio2", "2", "Noise", "4294967205"),
 OKV("ok_utilization_radio1", "1", "Utilization", "51"),
 OKV("ok_utilization_radio3", "3", "Utilization", "53"),
 OKV("ok_transmit_radio1", "1", "Transmit", "11"),
 OKV("ok_receive_self_radio2", "2", "ReceiveSelf", "22"),
 OKV("ok_receive_other_radio3", "3", "ReceiveOther", "33"),
 OKV("ok_chip_vendor_radio1", "1", "ChipsetVendor", "Acme1"),
 OKV("ok_chip_vendor_radio3", "3", "ChipsetVendor", "Acme3"),
 OKV("ok_bss_count_radio1", "1", "BSSNumberOfEntries", "2"),
 OKV("ok_bss_count_radio3", "3", "BSSNumberOfEntries", "6"),
 OKV("ok_temperature_radio1", "1", "X_AIRTIES_Temperature", "41"),
 OKV("ok_temperature_radio3", "3", "X_AIRTIES_Temperature", "43"),
 /* ---- current operating class count (capability / empty entries are skipped) ---- */
 OKV("ok_curop_count_radio1", "1", "CurrentOperatingClassProfileNumberOfEntries", "2"),
 OKV("ok_curop_count_radio2", "2", "CurrentOperatingClassProfileNumberOfEntries", "1"),
 OKV("ok_curop_count_radio3", "3", "CurrentOperatingClassProfileNumberOfEntries", "0"),
 /* ---- device selected by MAC alias ---- */
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.2.Utilization", false, false, 0, "52", 0, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", "Foo")),
 RJ("rej_param_lowercase", EV("1", "id")),
 {"rej_device_not_found", N "Device.9.Radio.1.ID", false, false, 25, NULL, 0, false},
 {"rej_device_alias_not_found", N "Device.[aa:bb:cc:dd:ee:ff].Radio.1.ID", false, false, 25, NULL, 0, false},
 {"rej_no_dm", EV("1", "ID"), false, true, 25, NULL, 0, false},
 {"rej_event_null", NULL, false, false, 2, NULL, 0, false},
 {"rej_pdata_null", EV("1", "ID"), true, false, 2, NULL, 0, false},
 RJ("rej_no_dot", "ID"),
 /* ---- [spec]: wrong behaviour, no abort (atoi reads the leading digits) ---- */
 {"rej_radio_1abc [spec]", EV("1abc", "ID"), false, false, 2, NULL, 0, false},
 {"rej_radio_2x [spec]", EV("2x", "ID"), false, false, 2, NULL, 0, false},
 /* ---- CRASH cases on the original handler (rejected, rc 2, after the fix) ---- */
 CR("rej_method_short", "X.ID"),
 CR("rej_path_without_device", N "ID"),
 CR("rej_path_without_radio", N "Device.1.ID"),
 CR("rej_radio_0", EV("0", "ID")),
 CR("rej_radio_4", EV("4", "ID")),
 CR("rej_radio_alias", EV("[x]", "ID")),
 CR("rej_radio_negative", EV("-1", "ID")),
 CR("rej_radio_huge", EV("1000000", "ID")),
 {"clamp_chip_vendor_no_nul", EV("1", "ChipsetVendor"), false, false, 0, NULL, 1, false},
 {"clamp_num_opclass_over_max", EV("1", "CurrentOperatingClassProfileNumberOfEntries"), false, false, 0, "2", 2, false},

 { NULL, NULL, false, false, 0, NULL, 0, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + RGI_LEFT, RGI_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_dm = NULL;
    if (tc->no_dm) return;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    for (int r = 1; r <= EM_MAX_BANDS; r++) {
        em_radio_info_t *ri = &dm->m_radio[r - 1].info;
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)r};
        memcpy(ri->id.ruid, m, 6);
        ri->enabled = (r != 2);
        ri->noise = -(89 + r);
        ri->utilization = (unsigned short)(50 + r);
        ri->transmit = (unsigned char)(10 + r);
        ri->receive_self = (unsigned char)(20 + r);
        ri->receive_other = (unsigned char)(30 + r);
        snprintf(ri->chip_vendor, sizeof(ri->chip_vendor), "Acme%d", r);
        ri->number_of_bss = 2 * r;
        ri->radio_temp = (unsigned char)(40 + r);
    }
    if (tc->variant == 1) memset(dm->m_radio[0].info.chip_vendor, 'A', sizeof(dm->m_radio[0].info.chip_vendor));
    static const struct { unsigned char radio; int type; } ocs[] = {
        {1, 1}, {1, 1}, {1, 2}, {2, 1}, {3, 2}, {0, 0},
    };
    for (unsigned int i = 0; i < sizeof(ocs) / sizeof(ocs[0]); i++) {
        dm_op_class_t *oc = &dm->m_op_class[i];
        unsigned char m[6] = {2, 0, 0, 0, 0, ocs[i].radio};
        memcpy(oc->info.id.ruid, m, 6);
        oc->info.id.type = (em_op_class_type_t)ocs[i].type;
    }
    dm->m_num_opclass = (tc->variant == 2) ? 100 : (unsigned int)(sizeof(ocs) / sizeof(ocs[0]));
    g_dm = dm;
}

void teardown(void)
{
    delete g_dm; g_dm = NULL;
}

} /* namespace rgi */

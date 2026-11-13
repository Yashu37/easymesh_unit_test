/*
 * TEST CASES / CONSTRUCTOR: construct_curops_get_inner
 *
 * event_name lives in name_store at offset COG_LEFT (runner poisons the bytes in front of it and
 * past its NUL). One device 1 (or the MAC alias 02:00:00:00:00:01) with radios 1..3 (RUID
 * 02:00:00:00:00:r) and this op class list:
 *   [0] radio 1 current  class 115 channel 36  tx 20     [3] radio 1 current  class 125 channel 149 tx 30
 *   [1] radio 1 capability class 81 channel 1  tx 10     [4] radio 2 current  class 128 channel 42  tx 24
 *   [2] NULL entry                                       [5] radio 3 current  class 130 channel 50  tx 27
 * so Radio.1.CurrentOperatingClass.1 is entry [0], .2 is entry [3] (capability / NULL entries are
 * skipped), Radio.2 .1 is [4], Radio.3 .1 is [5].
 *
 * expect_rc: 0 success, 2 invalid_input, 25 invalid_namespace. Cases marked [spec] are wrong
 * behaviour (an instance like "1abc" is read as 1 by atoi). The last 9 cases (method name shorter
 * than the Network prefix, path that stops before the Device / Radio / CurrentOperatingClass
 * instance, Radio instance 0 / 4 / 1000000 / alias / -1) ABORTED on the original handler; with
 * fixes 1-3 they are rejected (rc 2). A case flagged crash=true would run last and UNFORKED
 * (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "curops_get_inner.h"

namespace cog {

alignas(16) char name_store[COG_LEFT + COG_NAME_SZ + COG_PAD];

#define N "Device.WiFi.DataElements.Network."
#define EV(rad, ci, p) N "Device.1.Radio." rad ".CurrentOperatingClass." ci "." p
/* {name, event, no_pdata, no_dm, expect_rc, expect_val, crash} */
#define OKV(n, rad, ci, p, v) {n, EV(rad, ci, p), false, false, 0, v, false}
#define RJ(n, ev) {n, ev, false, false, 2, NULL, false}
#define RJC(n, ev) {n, ev, false, false, 2, NULL, false}

test_case_t suite[] = {
 /* ---- every parameter name ---- */
 OKV("ok_class", "1", "1", "Class", "115"),
 OKV("ok_channel", "1", "1", "Channel", "36"),
 OKV("ok_txpower", "1", "1", "TxPower", "20"),
 {"ok_timestamp", EV("1", "1", "TimeStamp"), false, false, 0, "TIMESTAMP", false},
 /* ---- which entry is selected ---- */
 OKV("ok_radio1_second_current", "1", "2", "Class", "125"),
 OKV("ok_radio1_second_channel", "1", "2", "Channel", "149"),
 OKV("ok_radio1_second_txpower", "1", "2", "TxPower", "30"),
 OKV("ok_radio2_first", "2", "1", "Class", "128"),
 OKV("ok_radio2_channel", "2", "1", "Channel", "42"),
 OKV("ok_radio3_first", "3", "1", "TxPower", "27"),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.2.CurrentOperatingClass.1.Class", false, false, 0, "128", false},
 {"ok_curop_alias_selects_nothing", EV("1", "[x]", "Class"), false, false, 2, NULL, false},
 /* ---- rejected ---- */
 RJ("rej_invalid_param", EV("1", "1", "Foo")),
 RJ("rej_curop_0", EV("1", "0", "Class")),
 RJ("rej_curop_3_of_2", EV("1", "3", "Class")),
 RJ("rej_curop_9", EV("1", "9", "Class")),
 RJ("rej_curop_negative", EV("1", "-1", "Class")),
 RJ("rej_radio2_curop_2", EV("2", "2", "Class")),
 {"rej_device_not_found", N "Device.9.Radio.1.CurrentOperatingClass.1.Class", false, false, 25, NULL, false},
 {"rej_device_alias_not_found", N "Device.[aa:bb:cc:dd:ee:ff].Radio.1.CurrentOperatingClass.1.Class", false, false, 25, NULL, false},
 {"rej_no_dm", EV("1", "1", "Class"), false, true, 25, NULL, false},
 {"rej_event_null", NULL, false, false, 2, NULL, false},
 {"rej_pdata_null", EV("1", "1", "Class"), true, false, 2, NULL, false},
 RJ("rej_no_dot", "Class"),
 /* ---- [spec]: wrong behaviour, no abort (atoi reads the leading digits) ---- */
 {"rej_curop_1abc [spec]", EV("1", "1abc", "Class"), false, false, 2, NULL, false},
 {"rej_radio_1abc [spec]", EV("1abc", "1", "Class"), false, false, 2, NULL, false},
 /* ---- were CRASH cases on the original handler (now rejected, rc 2) ---- */
 RJC("rej_method_short", "X.Class"),
 RJC("rej_path_without_device", N "Class"),
 RJC("rej_path_without_radio", N "Device.1.Class"),
 RJC("rej_path_without_curop", N "Device.1.Radio.1.Class"),
 RJC("rej_radio_0", EV("0", "1", "Class")),
 RJC("rej_radio_4", EV("4", "1", "Class")),
 RJC("rej_radio_huge", EV("1000000", "1", "Class")),
 RJC("rej_radio_alias", EV("[x]", "1", "Class")),
 RJC("rej_radio_negative", EV("-1", "1", "Class")),

 { NULL, NULL, false, false, 0, NULL, false }  /* sentinel */
};

static const oc_spec_t ocs_spec[] = {
    {1, 1, 115, 36, 20}, {1, 2, 81, 1, 10}, {0, 0, 0, 0, 0}, {1, 1, 125, 149, 30}, {2, 1, 128, 42, 24}, {3, 1, 130, 50, 27},
};

void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->event) snprintf(name_store + COG_LEFT, COG_NAME_SZ, "%s", tc->event);
    g_nset = 0; g_val[0] = '\0'; g_dm = NULL;
    if (tc->no_dm) return;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t;
    memset((void *)dm, 0, sizeof(*dm));
    for (int r = 0; r < EM_MAX_BANDS; r++) {
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(r + 1)};
        memcpy(dm->m_radio[r].info.id.ruid, m, 6);
    }
    for (unsigned int i = 0; i < sizeof(ocs_spec) / sizeof(ocs_spec[0]); i++) {
        const oc_spec_t *s = &ocs_spec[i];
        if (s->type == 0) { dm->ocs[dm->noc++] = NULL; continue; }
        dm_op_class_t *oc = new dm_op_class_t;
        memset((void *)oc, 0, sizeof(*oc));
        unsigned char m[6] = {2, 0, 0, 0, 0, s->radio};
        memcpy(oc->info.id.ruid, m, 6);
        oc->info.id.type = (em_op_class_type_t)s->type;
        oc->info.op_class = s->op_class; oc->info.channel = s->channel; oc->info.tx_power = s->tx_power;
        dm->ocs[dm->noc++] = oc;
    }
    g_dm = dm;
}

void teardown(void)
{
    if (!g_dm) return;
    for (unsigned int i = 0; i < g_dm->noc; i++) delete g_dm->ocs[i];
    delete g_dm; g_dm = NULL;
}

} /* namespace cog */

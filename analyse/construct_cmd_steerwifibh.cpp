/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_steerwifibh
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 exists (or the MAC alias 02:00:00:00:00:01).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). In the source the io_process() call is commented out, so an accepted
 * request is answered "Success" but never dispatched: the accept cases check rc + status only and
 * the case whose json_has is "DISPATCH" ([spec]) expects exactly one dispatch. Other [spec] cases:
 * TargetBSS is not validated as a MAC, a 33-character TargetBSS is truncated at 32, a negative
 * Channel is silently dropped. The last 3 cases (NULL method_name, method name shorter than the
 * Network prefix, path that stops before the Device instance) ABORTED on the original handler; with
 * fixes 1-2 they are rejected (rc 2). A case flagged crash=true would run last and UNFORKED
 * (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_steerwifibh.h"

namespace cwb {

alignas(16) char method_buf[256 + CWB_PAD];
ccs::bus_data_prop_t props_buf[CWB_MAXP];
alignas(16) char val_buf[CWB_MAXP][CWB_VAL_SZ + CWB_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.SteerWiFiBackhaul()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define TB(v) S("TargetBSS", v)
#define CH(v) I32("Channel", v)
#define TO(v) I32("TimeOut", v)
#define T1 "aa:bb:cc:dd:ee:ff"
#define BASE TB(T1), CH(36), TO(10)
#define OK(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, NULL, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {BASE, E0}, rc, NULL, false}
#define RJC(n, m) {n, m, false, false, {BASE, E0}, 2, NULL, false}

test_case_t suite[] = {
 /* ---- accepted (rc 0 + "Success"; the dispatch is commented out in the source, see [spec] below) ---- */
 OK("ok_basic", BASE),
 OK("ok_without_channel", TB(T1), TO(10)),
 OK("ok_channel_0", TB(T1), CH(0), TO(10)),
 OK("ok_timeout_0", TB(T1), CH(36), TO(0)),
 OK("ok_timeout_huge", TB(T1), CH(36), TO(2147483647)),
 OK("ok_channel_huge", TB(T1), CH(2147483647), TO(10)),
 OK("ok_params_any_order", TO(10), CH(36), TB(T1)),
 OK("ok_target_32_chars", R("TargetBSS", "T", 32), CH(36), TO(10)),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].SteerWiFiBackhaul()", false, false, {BASE, E0}, 0, NULL, false},
 {"ok_output_null", P, false, true, {BASE, E0}, 0, NULL, false},
 /* ---- rejected: method / path ---- */
 RP("rej_method_no_dot", "SteerWiFiBackhaul()", 2),
 RP("rej_wrong_method", N "Device.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.SteerWiFiBackhaul()", 25),
 /* ---- rejected: parameters ---- */
 {"rej_no_params", P, false, false, {E0}, 2, NULL, false},
 RJ("rej_missing_target", CH(36), TO(10)),
 RJ("rej_missing_timeout", TB(T1), CH(36)),
 RJ("rej_timeout_negative", TB(T1), CH(36), TO(-1)),
 RJ("rej_empty_target", TB(""), CH(36), TO(10)),
 RJ("rej_target_int_type", I32("TargetBSS", 5), CH(36), TO(10)),
 RJ("rej_channel_string_type", TB(T1), S("Channel", "36"), TO(10)),
 RJ("rej_timeout_string_type", TB(T1), CH(36), S("TimeOut", "10")),
 RJ("rej_unknown_prop", BASE, S("Foo", "bar")),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"ok_dispatched_to_dm [spec]", P, false, false, {BASE, E0}, 0, "DISPATCH", false},
 RJ("rej_target_not_mac [spec]", TB("garbage"), CH(36), TO(10)),
 RJ("rej_target_33_chars [spec]", R("TargetBSS", "T", 33), CH(36), TO(10)),
 RJ("rej_channel_negative [spec]", TB(T1), CH(-5), TO(10)),
 /* ---- were CRASH cases on the original handler (now rejected, rc 2) ---- */
 {"rej_method_null", NULL, false, false, {BASE, E0}, 2, NULL, false},
 RJC("rej_method_name_short", "X.SteerWiFiBackhaul()"),
 RJC("rej_path_without_device", N "SteerWiFiBackhaul()"),

 { NULL, NULL, false, false, {E0}, 0, NULL, false }  /* sentinel */
};

static void add_prop(const char *name, int kind, const char *s, int i, int len)
{
    ccs::bus_data_prop_t *p = &props_buf[num_props];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->name_len = (uint32_t)strlen(p->name);
    if (kind == 0 || kind == 5) {
        char *v = val_buf[num_props];
        memset(v, 0, CWB_VAL_SZ + CWB_PAD);
        size_t n;
        if (kind == 5) { memset(v, s[0], (size_t)len); n = (size_t)len + 1; }
        else { n = strlen(s) + 1; memcpy(v, s, n); }
        p->value.data_type = ccs::bus_data_type_string;
        p->value.raw_data.bytes = v;
        p->value.raw_data_len = (unsigned int)n;
    } else if (kind == 6) {
        p->value.data_type = (ccs::bus_data_type_t)100;     /* bus_data_type_boolean stand-in */
        p->value.raw_data.u8 = (uint8_t)i;
    } else {
        p->value.data_type = ccs::bus_data_type_int32;
        p->value.raw_data.i32 = i;
    }
    if (num_props > 0) props_buf[num_props - 1].next_data = p;
    num_props++;
}

void construct_input(const test_case_t *tc)
{
    memset(method_buf, 0, sizeof(method_buf));
    if (tc->method) snprintf(method_buf, 256, "%s", tc->method);
    set_ctrl(true);
    num_props = 0;
    for (int i = 0; tc->props[i].name != NULL; i++)
        add_prop(tc->props[i].name, tc->props[i].kind, tc->props[i].s, tc->props[i].i, tc->props[i].len);
}

} /* namespace cwb */

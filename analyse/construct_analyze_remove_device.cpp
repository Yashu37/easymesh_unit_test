/*
 * TEST CASES / CONSTRUCTOR: construct_analyze_remove_device
 *
 * The JSON is copied into ard::evt_buf = event header + subdoc.buff (the runner poisons everything past the
 * NUL and the event's guard field). pcmd[] is ard::pcmd_buf with EM_MAX_CMD (16) usable slots (the runner
 * poisons slot 16 onward). The data model holds ndev devices 02:00:00:00:00:01 .. ndev; the handler builds
 * one remove-device command per device that is not in DeviceList, and the recorded device list is
 * "<mac>;<mac>;..." (the removed devices, in model order). gen=1..3 build the over/at-limit DeviceLists:
 * 33 / 32 / 40 IDs.
 *
 * expect_num: number of commands built (0 = rejected / nothing to remove). Cases marked [spec] are wrong
 * behaviour (no abort): DeviceList that is a number or string (not an array) removes EVERY device (the array size is 0 so the
 * keep list is empty), an ID with trailing text is accepted. Cases named crash_* ABORT on the original
 * handler: more than 32 DeviceList entries (dev_mac_to_keep[32] overflow), an entry without a string ID
 * (string_to_macbytes(NULL) does strlen(NULL); a DeviceList that is an object has the same effect because
 * cJSON_GetArraySize() counts its members and GetArrayItem returns a member that has no "ID"), more than 32 devices to delete (devices_to_delete[32]
 * overflow) and 16 or more devices to delete (pcmd[16] overflow in the caller's array: the loop that
 * chains clone_for_next() writes pcmd[num] after the last command, so only 15 commands fit). They run last and
 * UNFORKED so a plain make stops with the ASan report (FORK_CRASH=1 forks each one).
 * Not tested (uninitialised stack data, not deterministic): ID strings that are not hex MACs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "analyze_remove_device.h"

namespace ard {

alignas(16) char evt_buf[ARD_EVT_SZ];
alignas(16) void *pcmd_buf[ARD_MAXCMD + ARD_PCMD_EXTRA];

#define W "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":"
#define T "}}}"
#define D(m) "{\"ID\":\"" m "\"}"
#define MAC1 "02:00:00:00:00:01"
#define MAC2 "02:00:00:00:00:02"
#define MAC3 "02:00:00:00:00:03"
/* {name, json, gen, ndev, expect_num, has, not_has, crash} */
#define OKC(n, j, nd, num, has, nhas) {n, j, 0, nd, num, has, nhas, false}

test_case_t suite[] = {
 /* ---- keep list selects the devices that stay ---- */
 OKC("ok_keep_first_of_3", W "[" D(MAC1) "]" T, 3, 2, "02:00:00:00:00:02;02:00:00:00:00:03;", MAC1),
 OKC("ok_keep_two_of_3", W "[" D(MAC1) "," D(MAC3) "]" T, 3, 1, "02:00:00:00:00:02;", MAC1),
 OKC("ok_keep_all", W "[" D(MAC1) "," D(MAC2) "," D(MAC3) "]" T, 3, 0, NULL, NULL),
 OKC("ok_keep_none_removes_all", W "[]" T, 3, 3, "02:00:00:00:00:01;02:00:00:00:00:02;02:00:00:00:00:03;", NULL),
 OKC("ok_keep_unknown_removes_all", W "[" D("aa:bb:cc:dd:ee:ff") "]" T, 2, 2, "02:00:00:00:00:01;02:00:00:00:00:02;", NULL),
 OKC("ok_keep_last", W "[" D(MAC3) "]" T, 3, 2, "02:00:00:00:00:01;02:00:00:00:00:02;", MAC3),
 OKC("ok_id_no_colons", W "[" D("020000000002") "]" T, 3, 2, "02:00:00:00:00:01;", MAC2),
 OKC("ok_id_uppercase", W "[" D("02:00:00:00:00:0A") "]" T, 10, 9, "02:00:00:00:00:09;", "02:00:00:00:00:0a"),
 OKC("ok_duplicate_ids", W "[" D(MAC1) "," D(MAC1) "]" T, 2, 1, "02:00:00:00:00:02;", MAC1),
 OKC("ok_extra_fields_ignored", W "[{\"ID\":\"" MAC1 "\",\"x\":1}],\"Other\":5" T, 2, 1, "02:00:00:00:00:02;", MAC1),
 OKC("ok_one_device_kept", W "[" D(MAC1) "]" T, 1, 0, NULL, NULL),
 OKC("ok_no_devices", W "[" D(MAC1) "]" T, 0, 0, NULL, NULL),
 OKC("ok_no_devices_empty_list", W "[]" T, 0, 0, NULL, NULL),
 /* ---- device without a data model is skipped ---- */
 /* (ndev 3, device 3 has no data model: variant handled by the constructor for ids >= 0x20 only) */
 /* ---- at the limits that still work ---- */
 {"ok_32_ids_all_kept", NULL, 2, 32, 0, NULL, NULL, false},
 OKC("ok_15_devices_removed", W "[]" T, 15, 15, "02:00:00:00:00:0f;", NULL),
 OKC("ok_14_devices_removed", W "[" D(MAC1) "]" T, 15, 14, "02:00:00:00:00:0f;", MAC1),
 /* ---- rejected input ---- */
 OKC("rej_not_json", "not json", 3, 0, NULL, NULL),
 OKC("rej_empty_text", "", 3, 0, NULL, NULL),
 OKC("rej_missing_wfa", "{\"other\":1}", 3, 0, NULL, NULL),
 OKC("rej_missing_network", "{\"wfa-dataelements:RemoveDevice\":{}}", 3, 0, NULL, NULL),
 OKC("rej_missing_devicelist", "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{}}}", 3, 0, NULL, NULL),
 OKC("rej_wfa_not_object_array", "{\"wfa-dataelements:RemoveDevice\":[]}", 3, 0, NULL, NULL),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"rej_devicelist_not_array [spec]", W "5" T, 0, 3, 0, NULL, NULL, false},
 {"rej_id_trailing_text [spec]", W "[" D(MAC1 ":99") "]" T, 0, 2, 0, NULL, NULL, false},
 /* ---- CRASH cases on the original handler (rejected / bounded after the fix) ---- */
 {"crash_devicelist_33_ids", NULL, 1, 3, 0, NULL, NULL, true},
 {"crash_devicelist_40_ids", NULL, 3, 3, 0, NULL, NULL, true},
 {"crash_devicelist_object", W "{\"ID\":\"" MAC1 "\"}" T, 0, 3, 0, NULL, NULL, true},
 {"crash_id_missing", W "[{}]" T, 0, 3, 0, NULL, NULL, true},
 {"crash_id_number", W "[{\"ID\":5}]" T, 0, 3, 0, NULL, NULL, true},
 {"crash_id_null", W "[{\"ID\":null}]" T, 0, 3, 0, NULL, NULL, true},
 {"crash_id_missing_second", W "[" D(MAC1) ",{\"name\":\"x\"}]" T, 0, 3, 0, NULL, NULL, true},
 {"crash_16_devices_to_delete", W "[]" T, 0, 16, 15, NULL, NULL, true},
 {"crash_17_devices_to_delete", W "[]" T, 0, 17, 15, NULL, NULL, true},
 {"crash_32_devices_to_delete", W "[]" T, 0, 32, 15, NULL, NULL, true},
 {"crash_33_devices_to_delete", W "[]" T, 0, 33, 15, NULL, NULL, true},
 {"crash_40_devices_to_delete", W "[]" T, 0, 40, 15, NULL, NULL, true},

 { NULL, NULL, 0, 0, 0, NULL, NULL, false }  /* sentinel */
};

static void gen_json(int gen, char *buf, size_t room)
{
    int n = (gen == 1) ? 33 : (gen == 2) ? 32 : 40;
    size_t l = (size_t)snprintf(buf, room, "{\"wfa-dataelements:RemoveDevice\":{\"Network\":{\"DeviceList\":[");
    for (int i = 0; i < n; i++)
        l += (size_t)snprintf(buf + l, room - l, "%s{\"ID\":\"02:00:00:00:%02x:%02x\"}", i ? "," : "", (i + 1) >> 8, (i + 1) & 0xff);
    snprintf(buf + l, room - l, "]}}}");
}

void construct_input(const test_case_t *tc)
{
    memset(evt_buf, 0, sizeof(evt_buf));
    char *buff = ((em_bus_event_t *)evt_buf)->u.subdoc.buff;
    size_t room = ARD_EVT_SZ - offsetof(em_bus_event_t, u.subdoc.buff);
    if (tc->gen) gen_json(tc->gen, buff, room);
    else snprintf(buff, room, "%s", tc->json);
    g_ndev = tc->ndev;
    memset(g_devs, 0, sizeof(g_devs)); memset(g_dms, 0, sizeof(g_dms));
    for (int i = 0; i < g_ndev && i < ARD_MAXDEV; i++) {
        unsigned char m[6] = {2, 0, 0, 0, 0, (unsigned char)(i + 1)};
        memcpy(g_devs[i].m_device_info.intf.mac, m, 6);
        snprintf(g_devs[i].m_device_info.id.net_id, sizeof(g_devs[i].m_device_info.id.net_id), "OneWifiMesh");
        memcpy(g_dms[i].mac, m, 6);
        g_dms[i].present = true;
    }
    g_num = 0;
}

void teardown(void) {}

} /* namespace ard */

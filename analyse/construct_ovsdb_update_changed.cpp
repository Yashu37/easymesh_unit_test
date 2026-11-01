/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_update_changed
 *
 * self->mon_type selects the branch; on MODIFY the field is looked up in
 * mon_json_old and, when present, both old and new values are dumped with
 * json_gets into v_old[256] / v_new[256]. field and mon_table are copied
 * into runner buffers (tail poisoned by the runner).
 *
 * Cases: NEW, DEL, ERROR, invalid type, MODIFY field absent in old,
 * MODIFY small values, MODIFY field missing in new (json_gets(NULL) ->
 * "json_gets() error"), MODIFY 252-char value (dump 254 chars incl.
 * quotes), MODIFY 253-char value (dump 255 + NUL = exactly 256, fits),
 * MODIFY 254-char value (dump 256 -> refused, "json_gets() error"), and
 * MODIFY with a 2000-element array value (refused).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   oucg_slot[2][OUC_SLOT_SZ + OUC_SLOT_PAD];
size_t oucg_len[2];
int    oucg_next;
char   ouc_field[OUC_STR_SZ];
char   ouc_table[OUC_STR_SZ];
ovsdb_update_monitor_t ouc_mon;

ovsdb_update_changed_test_case_t ovsdb_update_changed_suite[] = {
    /* name                 type                  old_kind val_len  changed old_len new_len */
    { "new",                OVSDB_UPDATE_NEW,       1,       3,      1,      0,     0 },
    { "del",                OVSDB_UPDATE_DEL,       1,       3,      1,      0,     0 },
    { "error",              OVSDB_UPDATE_ERROR,     1,       3,      0,      0,     0 },
    { "invalid_type",       7,                      1,       3,      0,      0,     0 },
    { "mod_field_absent",   OVSDB_UPDATE_MODIFY,    0,       3,      0,      0,     0 },
    { "mod_small",          OVSDB_UPDATE_MODIFY,    1,       3,      1,      5,     5 },
    { "mod_missing_new",    OVSDB_UPDATE_MODIFY,    2,       3,      1,      5,    17 },
    { "mod_value_252",      OVSDB_UPDATE_MODIFY,    1,     252,      1,    254,   254 },
    { "mod_value_253",      OVSDB_UPDATE_MODIFY,    1,     253,      1,     -1,    -1 },
    { "mod_value_254",      OVSDB_UPDATE_MODIFY,    1,     254,      1,     -1,    -1 },
    { "mod_array_2000",     OVSDB_UPDATE_MODIFY,    3,    2000,      1,     -1,    -1 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_update_changed_input(const ovsdb_update_changed_test_case_t *tc)
{
    snprintf(ouc_field, sizeof(ouc_field), "ssid");
    snprintf(ouc_table, sizeof(ouc_table), "Wifi_VIF_Config");

    if (ouc_mon.mon_json_new) json_decref((json_t *)ouc_mon.mon_json_new);
    if (ouc_mon.mon_json_old) json_decref((json_t *)ouc_mon.mon_json_old);
    memset(&ouc_mon, 0, sizeof(ouc_mon));
    ouc_mon.mon_type  = (ovsdb_update_type_t)tc->mon_type;
    ouc_mon.mon_table = ouc_table;

    json_t *vo, *vn;
    if (tc->old_kind == 3) {
        vo = json_array(); vn = json_array();
        for (int i = 0; i < tc->val_len; i++) { json_array_append_new(vo, json_integer(i)); json_array_append_new(vn, json_integer(i)); }
    } else {
        char *s = (char *)malloc((size_t)tc->val_len + 1);
        memset(s, 'o', (size_t)tc->val_len); s[tc->val_len] = 0;
        vo = json_string(s);
        memset(s, 'n', (size_t)tc->val_len);
        vn = json_string(s);
        free(s);
    }
    json_t *jo = json_object(), *jn = json_object();
    if (tc->old_kind != 0) json_object_set_new(jo, "ssid", vo); else json_decref(vo);
    if (tc->old_kind != 2) json_object_set_new(jn, "ssid", vn); else json_decref(vn);
    json_object_set_new(jn, "enabled", json_true());
    ouc_mon.mon_json_old = jo;
    ouc_mon.mon_json_new = jn;

    oucg_len[0] = oucg_len[1] = 0;
    oucg_next = 0;
}

/*
 * HANDLER: osp_unit_dhcpc_hostname_get
 *
 * Function copied VERBATIM from OneWifi lib/datapipeline/osp_unit_rdk.c.
 * No fixes. It declares two VLAs (serial_num[buffsz], model_name[buffsz]),
 * fills them via osp_unit_serial_get/osp_unit_model_get (bounded by
 * sizeof), and combines them into the caller's buff with bounded snprintf.
 *
 * Scaffolding (NOT the function under test): osp_unit_serial_get and
 * osp_unit_model_get are STUBBED (the real ones read RDK device info).
 * The stubs write a controlled value bounded by buffsz, and can be made to
 * "fail" to exercise the error paths. LOG is a no-op stub.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

/* test knobs (defined in the construct file) */
extern const char *osp_stub_serial;
extern const char *osp_stub_model;
extern int         osp_stub_serial_ok;
extern int         osp_stub_model_ok;

static bool osp_unit_serial_get(char *buff, size_t buffsz)
{
    if (!osp_stub_serial_ok) return false;
    snprintf(buff, buffsz, "%s", osp_stub_serial);
    return true;
}
static bool osp_unit_model_get(char *buff, size_t buffsz)
{
    if (!osp_stub_model_ok) return false;
    snprintf(buff, buffsz, "%s", osp_stub_model);
    return true;
}

/* --- copied verbatim from lib/datapipeline/osp_unit_rdk.c --- */
bool osp_unit_dhcpc_hostname_get(void *buff, size_t buffsz)
{
    char serial_num[buffsz];
    char model_name[buffsz];

    memset(serial_num, 0, (sizeof(char) * buffsz));
    memset(model_name, 0, (sizeof(char) * buffsz));

    if (!osp_unit_serial_get(serial_num, sizeof(serial_num)))
    {
        LOG(ERR, "Unable to get serial number");
        return false;
    }
    if (!osp_unit_model_get(model_name, sizeof(model_name)))
    {
        LOG(ERR, "Unable to get model name");
        return false;
    }

    snprintf(buff, buffsz, "%s_%s", serial_num, model_name);

    return true;
}

/*
 * HANDLER: radio_get_name_from_cfg
 *
 * Function copied VERBATIM from OneWifi lib/datapipeline/dpp_types.h
 * (a static inline there), together with its helper radio_get_name_from_type
 * (also verbatim). No fixes.
 *
 * radio_get_name_from_cfg snprintf()s "<type> <phy_name>" into a static
 * name[RADIO_IFNAME_LEN + 1 + RADIO_NAME_LEN] (bounded). It reads
 * radio_cfg->type and radio_cfg->phy_name (caller-owned; poisoned by the
 * runner). The internal static name[] is auto-guarded by ASan.
 *
 * Scaffolding: radio_type_t / radio_entry_t / size + string #defines come
 * from common.h (minimal versions carrying the two fields the function
 * uses). radio_get_name_from_cfg is made extern (not static inline) so the
 * test TU can call it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/datapipeline/dpp_types.h --- */
static inline char * radio_get_name_from_type(radio_type_t radio_type)
{
    switch (radio_type)
    {
        case RADIO_TYPE_2G:  return (char *)RADIO_TYPE_STR_2G;  break;
        case RADIO_TYPE_5G:  return (char *)RADIO_TYPE_STR_5G;  break;
        case RADIO_TYPE_5GL: return (char *)RADIO_TYPE_STR_5GL; break;
        case RADIO_TYPE_5GU: return (char *)RADIO_TYPE_STR_5GU; break;
        case RADIO_TYPE_6G:  return (char *)RADIO_TYPE_STR_6G;  break;
        default:             break;
    }
    return NULL;
}

char *radio_get_name_from_cfg(radio_entry_t *radio_cfg)
{
    static char name[RADIO_IFNAME_LEN + 1 + RADIO_NAME_LEN]; // For space between the names

    if (NULL == radio_cfg) {
        return NULL;
    }
    memset (name, 0, sizeof(name));

    snprintf(name, sizeof(name), "%s %s",
            radio_get_name_from_type(radio_cfg->type),
            radio_cfg->phy_name);

    return name;
}

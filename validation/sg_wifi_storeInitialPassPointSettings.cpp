/*
 * HANDLER: wifi_storeInitialPassPointSettings (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:105-134 (~/Desktop/G/rdk-wifi-hal), compiled with FEATURE_SUPPORT_PASSPOINT defined (without it the function is empty).  This file holds the
 * ORIGINAL code (no fixes).  For ap index 0 .. MAX_AP_INDEX-1 (15) it prints a debug line, reads the five HS2 settings (country IE, layer-2 traffic inspection, downstream group address, BSS load, proxy
 * ARP) through the getters and stores them in the static hs2Settings[ap_index]; getter results are not checked.
 *
 * Scaffolding only: MAX_AP_INDEX is 15 (wifi_hal_anqp.c:57); the statics hs2Settings[MAX_AP_INDEX + 1] / hs2SettingsStored are declared like wifi_hal_anqp.c:63-64 and exposed by hwr_wsp_hs2() /
 * hwr_wsp_stored(); the five getters and wifi_anqp_dbg_print are recording stubs; renamed hwr_sg_wifi_storeInitialPassPointSettings.
 */
#include "hwr_wsp.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define FEATURE_SUPPORT_PASSPOINT 1
#define MAX_AP_INDEX 15
hwr_wsp_world_t hwr_wsp_world;
static wifi_HS2Settings_t hs2Settings[MAX_AP_INDEX + 1];
static BOOL hs2SettingsStored;
extern "C" wifi_HS2Settings_t *hwr_wsp_hs2(int *count) { *count = MAX_AP_INDEX + 1; return hs2Settings; }
extern "C" BOOL *hwr_wsp_stored(void) { return &hs2SettingsStored; }

static INT hwr_wsp_get(int kind, INT apIndex, BOOL *out)
{
	hwr_wsp_world_t *w = &hwr_wsp_world;
	w->calls[kind]++;
	if (w->seq_n < (int)(sizeof(w->seq_kind) / sizeof(int))) { w->seq_kind[w->seq_n] = kind; w->seq_ap[w->seq_n] = apIndex; w->seq_n++; }
	if (out == NULL) { w->null_out++; return -1; }
	if (w->fail_kind == kind) return -1;
	*out = w->val[kind][apIndex];
	return 0;
}
static INT wifi_getCountryIe(INT apIndex, BOOL *enabled) { return hwr_wsp_get(0, apIndex, enabled); }
static INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled) { return hwr_wsp_get(1, apIndex, enabled); }
static INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled) { return hwr_wsp_get(2, apIndex, disabled); }
static INT wifi_getBssLoad(INT apIndex, BOOL *enabled) { return hwr_wsp_get(3, apIndex, enabled); }
static INT wifi_getProxyArp(INT apIndex, BOOL *enabled) { return hwr_wsp_get(4, apIndex, enabled); }
/* wifi_anqp_dbg_print(level, "%s:%d:...:   %d\n", __func__, __LINE__, ap_index): records the ap index */
static void hwr_wsp_dbg(int level, const char *format, ...)
{
	va_list ap; hwr_wsp_world_t *w = &hwr_wsp_world;
	va_start(ap, format);
	(void)va_arg(ap, const char *); (void)va_arg(ap, int);
	{ int idx = va_arg(ap, int); if (w->dbg_calls < HWR_WSP_MAXAP + 8) w->dbg_ap[w->dbg_calls] = idx; }
	va_end(ap);
	w->dbg_calls++;
}
#define wifi_anqp_dbg_print hwr_wsp_dbg
#define wifi_storeInitialPassPointSettings hwr_sg_wifi_storeInitialPassPointSettings

extern "C" {
/* --- wifi_hal_anqp.c:105-134 --- */
void wifi_storeInitialPassPointSettings()
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    int ap_index;
    BOOL _countryIe;
    BOOL _layer2TIF;
    BOOL _downStreamGroupAddress;
    BOOL _bssLoad;
    BOOL _proxyArp;

    for (ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++)
    {
        wifi_anqp_dbg_print(1, "%s:%d:Storing initial HS2 Values:   %d\n", __func__, __LINE__, ap_index);
        wifi_getCountryIe(ap_index, &_countryIe);
        hs2Settings[ap_index].countryIe = _countryIe;

        wifi_getLayer2TrafficInspectionFiltering(ap_index, &_layer2TIF);
        hs2Settings[ap_index].layer2TIF = _layer2TIF;

        wifi_getDownStreamGroupAddress(ap_index, &_downStreamGroupAddress);
        hs2Settings[ap_index].downStreamGroupAddress = _downStreamGroupAddress;

        wifi_getBssLoad(ap_index, &_bssLoad);
        hs2Settings[ap_index].bssLoad = _bssLoad;

        wifi_getProxyArp(ap_index, &_proxyArp);
        hs2Settings[ap_index].proxyArp = _proxyArp;
    }
#endif
}
}

/* hwr_wsp.h - plumbing for the sg_wifi_storeInitialPassPointSettings harness (src/wifi_hal_anqp.c, FEATURE_SUPPORT_PASSPOINT build).
 * wifi_HS2Settings_t is declared exactly like wifi_hal_rdk.h:144 and BOOL / INT are the REAL types.  The five getters wifi_getCountryIe / wifi_getLayer2TrafficInspectionFiltering /
 * wifi_getDownStreamGroupAddress / wifi_getBssLoad / wifi_getProxyArp (halinterface wifi_hal_ap.h) are recording stubs that fill their output from a runner table (or leave it untouched when failing);
 * wifi_anqp_dbg_print is a recording stub.  The function-static hs2Settings[MAX_AP_INDEX + 1] / hs2SettingsStored live in the handler file and are exposed through hwr_wsp_hs2() for poisoning and checks. */
#ifndef HWR_WSP_H
#define HWR_WSP_H
#include "hwr_defs.h"
#define HWR_WSP_MAXAP 15
typedef struct _wifi_HS2Settings_t
{
    BOOL countryIe;
    BOOL layer2TIF;
    BOOL downStreamGroupAddress;
    BOOL bssLoad;
    BOOL proxyArp;
}wifi_HS2Settings_t;
typedef struct {
	BOOL val[5][HWR_WSP_MAXAP];            /* what each getter reports per ap index */
	int fail_kind;                          /* getter kind that fails (output untouched, returns -1), -1: none */
	int calls[5]; int seq_n; int seq_kind[5 * HWR_WSP_MAXAP + 8], seq_ap[5 * HWR_WSP_MAXAP + 8]; int null_out;
	int dbg_calls, dbg_ap[HWR_WSP_MAXAP + 8];
	void *unrelated[4];                     /* poisoned: the function must not touch it */
} hwr_wsp_world_t;
extern hwr_wsp_world_t hwr_wsp_world;
extern "C" wifi_HS2Settings_t *hwr_wsp_hs2(int *count);
extern "C" BOOL *hwr_wsp_stored(void);
extern "C" void hwr_sg_wifi_storeInitialPassPointSettings(void);
typedef struct {
	const char *test_name;
	int pattern;                   /* values reported by the getters: 0 all 0, 1 all 1, 2 alternating by ap + kind, 3 all 2, 4 all 0xFF */
	int pattern2;                  /* a second call with this pattern (-1: none) */
	int fail_kind;                 /* getter kind that fails (0 countryIe, 1 layer2TIF, 2 downStreamGroupAddress, 3 bssLoad, 4 proxyArp), -1: none */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsp_case_t;
extern hwr_wsp_case_t sg_wifi_storeInitialPassPointSettings_suite[];
extern "C" void run_all_tests_sg_wifi_storeInitialPassPointSettings(void);
#endif

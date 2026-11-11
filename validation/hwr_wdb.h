/* hwr_wdb.h - plumbing for the sg_wifi_dpp_dbg_print harness (src/wifi_hal_dpp.c).
 * The function gates on access("/nvram/wifiDppDbg"), builds "<time> <message>" in a 2048-byte stack buffer and appends it to /tmp/wifiDPP through a function-static FILE *.  access() and fopen() are
 * replaced by runner-controlled stubs (macros in the handler file; fopen returns the runner's temp file or NULL), get_formatted_time is a deterministic stand-in (the real one,
 * wifi_hal_rdk_util.c:106, writes at most 128 bytes).  fputs / fflush / strcat / vsprintf are the real libc functions. */
#ifndef HWR_WDB_H
#define HWR_WDB_H
#include "hwr_defs.h"
#include <stdio.h>
#include <stdarg.h>
#define HWR_WDB_TS "240101-00:00:00.000000"      /* what get_formatted_time writes (22 characters) */
typedef struct {
	int access_ok;                 /* access("/nvram/wifiDppDbg", R_OK) result is 0 */
	int fopen_ok;                  /* fopen("/tmp/wifiDPP", "a+") returns the runner's file */
	int access_calls, fopen_calls, time_calls;
	FILE *file;
	void *unrelated[4];            /* poisoned: the function must not touch it */
} hwr_wdb_world_t;
extern hwr_wdb_world_t hwr_wdb_world;
extern "C" void hwr_sg_wifi_dpp_dbg_print(char *format, ...);
typedef struct {
	const char *test_name;
	int access_ok;                 /* the debug flag file is readable */
	int fopen_ok;                  /* /tmp/wifiDPP can be opened (only matters while the static FILE * is still NULL) */
	int msg_len;                   /* length of the "%s" argument; -1: format is NULL */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdb_case_t;
extern hwr_wdb_case_t sg_wifi_dpp_dbg_print_suite[];
extern "C" void run_all_tests_sg_wifi_dpp_dbg_print(void);
#endif

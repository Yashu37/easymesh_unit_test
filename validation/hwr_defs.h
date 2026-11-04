/* hwr_defs.h - harness plumbing for the hal_ipc_wifi_wrappers.c functions (self-contained, no common.h) */
#ifndef HWR_DEFS_H
#define HWR_DEFS_H
#include "hso_hal_ipc.h"
#define HWR_LOG_SZ   256
#define HWR_LOG_USE  128
#define HWR_GUARD_SZ 64
extern char          hwr_log_buf[HWR_LOG_SZ];
extern unsigned char hwr_guard_slab[HWR_GUARD_SZ];   /* runner-owned, fully poisoned during the call: the function must not touch it */
extern "C" void hwr_print(int level, const char *format, ...);
#endif

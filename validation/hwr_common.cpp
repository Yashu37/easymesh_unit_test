/*
 * hwr_common.cpp - shared plumbing of the hal_ipc_wifi_wrappers.c harnesses: the log sink used by the
 * wifi_hal_dbg_print / wifi_hal_error_print macros of the functions under test (a runner-poisoned slot).
 */
#include <stdarg.h>
#include "hwr_defs.h"

char          hwr_log_buf[HWR_LOG_SZ];
unsigned char hwr_guard_slab[HWR_GUARD_SZ];

extern "C" void hwr_print(int level, const char *format, ...)
{
	char tmp[1024]; va_list ap; size_t used = strlen(hwr_log_buf);
	(void)level;
	va_start(ap, format); vsnprintf(tmp, sizeof(tmp), format, ap); va_end(ap);
	if (used < HWR_LOG_USE - 1) snprintf(hwr_log_buf + used, HWR_LOG_USE - used, "%s", tmp);   /* appended, bounded to the first HWR_LOG_USE bytes */
}

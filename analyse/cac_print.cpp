/*
 * HANDLER: cac_print
 *
 * Function copied VERBATIM from OneWifi source/apps/cac/wifi_cac.c. No fixes.
 * Local buff[256]:
 *   - get_formatted_time(buff)                 -> ~22-char timestamp
 *   - strncat(buff, " ", strlen(buff))         -> appends one space
 *   - vsprintf(&buff[strlen(buff)], format, …) -> UNBOUNDED write into buff
 *
 * The vsprintf is unbounded: a caller format/args longer than the remaining
 * space overflows buff[256]. buff is an internal stack array (ASan stack
 * redzones). The RUNNER poisons the caller's format-arg buffer tail; the
 * log file path is redirected to a scratch temp file.
 *
 * Scaffolding (NOT the function under test): get_formatted_time copied
 * verbatim from source/utils/wifi_util.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include "common.h"

/* --- scaffolding --- */
#define CAC_LOG_PATH  cac_log_path   /* real: "/rdklogs/logs/wifiConnAdmissionCtrl.txt" */

/* verbatim from source/utils/wifi_util.c */
static char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = (struct tm *)localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lld", tmp, (long long)tv_now.tv_usec);
    return time;
}

/* --- copied verbatim from source/apps/cac/wifi_cac.c (log path redirected) --- */
void cac_print(char *format, ...)
{
    char buff[256] = {0};
    va_list list;
    FILE *fpg = NULL;

    get_formatted_time(buff);
    strncat(buff, " ", strlen(buff));

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    fpg = fopen(CAC_LOG_PATH, "a+");
    if (fpg == NULL) {
        return;
    }
    fputs(buff, fpg);
    fflush(fpg);
    fclose(fpg);
}

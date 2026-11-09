/*
 * HANDLER: wifi_nvram_defaultRead (platform/raspberry-pi, identical code in platform/wifi-emulator/platform_emulator.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/raspberry-pi/platform_pi.c:56-91 (~/Desktop/G/rdk-wifi-hal; wifi-emulator/platform_emulator.c:54-89 holds the
 * same text).  This file holds the ORIGINAL code with fix 1 applied
 * (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer): sprintf replaced by snprintf(cmd, MAX_CMD_SIZE, ...).  It builds the shell command "grep '<key>=' /nvram/wifi_defaults.txt" with sprintf into
 * char cmd[MAX_CMD_SIZE = 1024], runs it through _syscmd and copies the value after the first '=' of the first output line into out.
 *
 * DIFFERENCE from banana-pi: the banana-pi version formats the command with snprintf(cmd, MAX_CMD_SIZE, ...); this version uses an UNBOUNDED sprintf, so a key
 * of 991 characters or more (6 + len + 27 >= 1024 + NUL) overflows cmd on the stack.  The other findings of the banana-pi version (#80 shell injection through
 * the key, #81 substring / regex key match, #82 unbounded copy into out / NULL out / over-long line) are in the same code and apply here too; they are not
 * re-run in this harness (the function keeps its 2-argument signature, so the "out size" fix cannot be exercised).
 *
 * Scaffolding only: _syscmd (src/wifi_hal_hostapd.c, popen + fgets) is a stub that records the command and returns the runner's canned reply / result, so the
 * function's own logic is what is tested and no shell is run; the print macro maps to the log sink hwr_print.  Renamed hwr_rp_wifi_nvram_defaultRead because
 * the other platforms define the same name.
 */
#include "hwr_nvd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024

hwr_nvd_world_t hwr_nvd_world;

extern "C" int hwr_nvd_syscmd(char *cmd, char *retBuf, int retBufSize)
{
	hwr_nvd_world_t *w = &hwr_nvd_world;

	w->calls++;
	w->cmd_len = strlen(cmd);
	snprintf(w->cmd, sizeof(w->cmd), "%s", cmd);
	if (w->reply != NULL && retBufSize > 0) snprintf(retBuf, retBufSize, "%s", w->reply);
	return w->ret;
}
#define _syscmd hwr_nvd_syscmd
#define wifi_nvram_defaultRead hwr_rp_wifi_nvram_defaultRead

/* --- platform_pi.c:56-91 --- */
extern "C" {
int wifi_nvram_defaultRead(char *in,char *out)
{
    char buf[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *position;

    /* start fix 1 */
    snprintf(cmd,MAX_CMD_SIZE,"grep '%s=' /nvram/wifi_defaults.txt",in);
    /* end fix 1 */
    if(_syscmd(cmd,buf,sizeof(buf)) == -1)
    {
        wifi_hal_dbg_print("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return -1;
    }

    if (buf[0] == NULL_CHAR)
        return -1;
    position = buf;
    while(*position != NULL_CHAR)
    {
        if (*position == NEW_LINE)
        {
            *position = NULL_CHAR;
            break;
        }
        position++;
    }
    position = strchr(buf, '=');
    if (position == NULL)
    {
        wifi_hal_dbg_print("Line %d: invalid line '%s'",__LINE__, buf);
        return -1;
    }
    *position = NULL_CHAR;
    position++;
    strncpy(out,position,strlen(position)+1);
    return 0; 
}
}

/*
 * HANDLER: wifi_nvram_defaultRead
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:55-89 (~/Desktop/G/rdk-wifi-hal).  With
 * RDK_NVR_FIX 0 it is the VERBATIM original (reproduces the findings); with RDK_NVR_FIX 1 it carries FIX 1..3 below
 * (the fixed function takes the size of the output buffer as a third argument).
 *
 * The function reads "key=value" from /nvram/wifi_defaults.txt by running `grep '<key>=' /nvram/wifi_defaults.txt` through
 * _syscmd().  _syscmd (src/wifi_hal_hostapd.c:53) is copied VERBATIM, so the command really runs in a shell with a real
 * grep; the only redirection is the file path: the runner writes the case's file content to a temporary directory and
 * the stub hwr_nvr_syscmd / hwr_nvr_fopen replace "/nvram/wifi_defaults.txt" with that path in the command.  The
 * defines at the top of platform.c are copied verbatim; the prints are the real macros over the log sink.  The function
 * under test is renamed hwr_wifi_nvram_defaultRead (the other platforms define the same name).
 */
#include "hwr_nvr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 1 = with FIX 1..3 (3-argument function), 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_NVR_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wpa_printf(level, ...)             hwr_print(1, __VA_ARGS__)
#define MSG_ERROR 0

#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024

/* --- _syscmd copied verbatim from src/wifi_hal_hostapd.c:53 --- */
#define _syscmd hwr_nvr_real_syscmd
extern "C" {
int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0;

    if ((f = popen(cmd, "r")) == NULL) {
        wpa_printf(MSG_ERROR, "popen %s error\n", cmd);
        return -1;
    }

    while(!feof(f)) {
        *ptr = 0;
        if(bufSize>=128) {
                bufbytes=128;
        } else {
                bufbytes=bufSize-1;
        }
        fgets(ptr,bufbytes,f);
        readbytes=strlen(ptr);
        if( readbytes== 0)
                break;
        bufSize-=readbytes;
        ptr += readbytes;
    }
    pclose(f);
    return 0;
}
}
#undef _syscmd

#define _syscmd                    hwr_nvr_syscmd
#define fopen                      hwr_nvr_fopen
#define wifi_nvram_defaultRead     hwr_wifi_nvram_defaultRead

/* --- copied from platform.c:55 --- */
extern "C" {
#if RDK_NVR_FIX
int wifi_nvram_defaultRead(char *in, char *out, size_t out_size)
{
    /* FIX 1: the function built a shell command from the key (grep '%s=' ...) and used the first line that merely
     * CONTAINED "key=" as a substring / regular expression: a key with a quote broke out of the quoting and ran
     * commands (command injection), a longer key that ends in the wanted one ("xwps_pin=", "#wps_pin=",
     * "old_bpi_wifi_password=") or a line that has "key=" in its value returned the WRONG key's value, and a key with
     * regex characters matched other keys.  The file is now read directly (no shell) and a line only matches when
     * the text before its first '=' is exactly the key.
     * FIX 2: out was written without a NULL check and without a size (strncpy bounded by the source length), so a value
     * longer than the caller's buffer (output_val is BPI_LEN_32 in platform_pre_create_vap) overflowed it.  The
     * function takes the size of out and returns -1, leaving out untouched, when the value (with its NUL) does not fit.
     * FIX 3: a line longer than the 127-byte read buffer was silently truncated and returned as success; it is
     * rejected now. */
    char line[MAX_BUF_SIZE + 2];
    size_t key_len;
    FILE *fp;
    int ret = -1;

    if (in == NULL || out == NULL || out_size == 0 || in[0] == NULL_CHAR)
    {
        wifi_hal_dbg_print("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return -1;
    }
    key_len = strlen(in);
    if ((fp = fopen("/nvram/wifi_defaults.txt", "r")) == NULL)
    {
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        size_t len = strlen(line);
        int too_long = 0;

        if (len > 0 && line[len - 1] == NEW_LINE)
        {
            line[--len] = NULL_CHAR;
        }
        else if (!feof(fp))
        {
            int c;
            while ((c = fgetc(fp)) != EOF && c != NEW_LINE);
            too_long = 1;
        }
        if (len > MAX_BUF_SIZE - 1)
            too_long = 1;
        if (strncmp(line, in, key_len) == 0 && line[key_len] == '=')
        {
            if (too_long)
            {
                wifi_hal_dbg_print("Line %d: value of '%s' is too long\n",__LINE__, in);
                break;
            }
            if (strlen(line + key_len + 1) + 1 > out_size)
            {
                wifi_hal_dbg_print("Line %d: value of '%s' does not fit in %zu bytes\n",__LINE__, in, out_size);
                break;
            }
            memcpy(out, line + key_len + 1, strlen(line + key_len + 1) + 1);
            ret = 0;
            break;
        }
    }
    fclose(fp);
    return ret;
}
#else
int wifi_nvram_defaultRead(char *in,char *out)
{
    char buf[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *position;

    snprintf(cmd,MAX_CMD_SIZE,"grep '%s=' /nvram/wifi_defaults.txt",in);
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
#endif
}

extern "C" int hwr_nvr_call(char *in, char *out, size_t out_size)
{
#if RDK_NVR_FIX
    return wifi_nvram_defaultRead(in, out, out_size);
#else
    (void)out_size;
    return wifi_nvram_defaultRead(in, out);
#endif
}

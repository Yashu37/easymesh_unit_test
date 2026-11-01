/*
 * HANDLER: os_nif_list_get
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_nif_linux.c. No fixes.
 * Local arrays:
 *   - buf[256]   filled by fgets(buf, sizeof(buf), ...)  -> bounded
 *   - rm[2]      filled by regexec with nmatch = ARRAY_LEN(rm) = 2 -> bounded
 *   - os_nif_list_net_dev[2] static regex list, walked until re_str == NULL
 * The interface name is copied into n->le_ifname[64] by os_reg_match_cpy()
 * with destsz = sizeof(n->le_ifname), which truncates to 63 chars.
 *
 * Scaffolding (NOT the function under test):
 *   - os_reg_list_match / os_reg_match_cpy copied verbatim from
 *     lib/osa/os_regex.c (they do the regex match and the copy).
 *   - OS_REG_LIST_ENTRY: same fields as lib/osa/os_regex.h, but listed in
 *     declaration order because C++ rejects out-of-order designators.
 *   - fopen() -> onlg_fopen(): "/proc/net/dev" is served from a runner-owned
 *     test buffer (fmemopen), so each case can feed crafted content.
 *   - malloc()/free() -> runner-owned entry pool whose tail past
 *     sizeof(struct os_nif_list_entry) is poisoned by the runner.
 *   - os_nif_list_free copied verbatim (frees the list on error / cleanup).
 *   - ds_list_* minimal stub in common.h; LOG no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <regex.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

#define ARRAY_SIZE(x)       ((unsigned int)(sizeof(x) / sizeof(x[0])))   /* lib/const/const.h */
#define ARRAY_LEN(x)  ((int)ARRAY_SIZE(x))                               /* lib/const/const.h */

typedef struct                                                           /* lib/osa/os_regex.h */
{
    const char*     re_str;
    int32_t         re_id;

    regex_t         __re_ex;
    uint32_t        __re_flags;
} os_reg_list_t;

#define OS_REG_LIST_ENTRY(id, str)      \
{                                       \
    .re_str = (str),                    \
    .re_id = (id),                      \
    .__re_flags = 0x0                   \
}
#define OS_REG_LIST_END(id)   OS_REG_LIST_ENTRY(id, NULL)
#define OS_REG_FLAG_INIT      (1 << 0)
#define OS_REG_FLAG_INVALID   (1 << 1)      /* Relist entry is invalid */

/* copied verbatim from lib/osa/os_regex.c */
int os_reg_list_match(
        os_reg_list_t*  relist,
        char*           str,
        regmatch_t*     pmatch,
        size_t          nmatch)
{
    os_reg_list_t *re;

    for (re = relist; re->re_str != NULL; re++)
    {
        /* Compile the regular expression */
        if (!(re->__re_flags & OS_REG_FLAG_INIT))
        {
            re->__re_flags |= OS_REG_FLAG_INIT;

            if (regcomp(&re->__re_ex, re->re_str, REG_EXTENDED) != 0)
            {
                re->__re_flags |= OS_REG_FLAG_INVALID;
                LOG(ERR, "Error compiling regular expression::regex=%s", re->re_str);
                continue;
            }
        }

        /* Skip invalid entries */
        if (re->__re_flags & OS_REG_FLAG_INVALID)
        {
            continue;
        }

        if (regexec(&re->__re_ex, str, nmatch, pmatch, 0) == 0)
        {
            break;
        }
    }

    /*
     * The last entry (re->re_str == NULL) defines what value
     * is returned in case there is no match
     */
    return re->re_id;
}

/* copied verbatim from lib/osa/os_regex.c */
void os_reg_match_cpy(
        char*       dest,
        size_t      destsz,
        const char* src,
        regmatch_t  srm)
{
    size_t len = 0;

    if (srm.rm_eo < 0 || srm.rm_so < 0)
    {
        *dest = '\0';
    }

    len = srm.rm_eo - srm.rm_so;
    if (len >= destsz)
    {
        len = destsz - 1;
    }

    memcpy(dest, src + srm.rm_so, len);
    dest[len] = '\0';
}

/* fopen stub: serve /proc/net/dev from the runner's test buffer */
static FILE *onlg_fopen(const char *path, const char *mode)
{
    if (onlg_use_real)
        return fopen(path, mode);
    if (onlg_fopen_fail)
        return NULL;
    if (onlg_data_len == 0)
        return fmemopen((void *)"", 1, mode);   /* empty file (just NUL -> fgets sees EOF) */
    return fmemopen(onlg_data, onlg_data_len, mode);
}

/* malloc/free stubs: hand out runner-owned pool slots (poisoned tails) */
static void *onlg_malloc(size_t sz)
{
    if (sz != sizeof(struct os_nif_list_entry) || onlg_pool_used >= ONLG_POOL_SLOTS)
        return NULL;
    return onlg_pool[onlg_pool_used++];
}
static void onlg_free(void *p) { (void)p; /* pool memory, nothing to free */ }

#define fopen(p, m)  onlg_fopen((p), (m))
#define malloc(s)    onlg_malloc(s)
#define free(p)      onlg_free(p)

/* --- copied verbatim from lib/osa/os_nif_linux.c --- */
void os_nif_list_free(ds_list_t* list);

bool os_nif_list_get(ds_list_t *list)
{
    struct os_nif_list_entry*   n;

    bool               retval = false;
    FILE*                       fnetdev = NULL;
    char                        buf[256];

    /*
     * Parse the netwokr device list from /proc/net/dev
     */
    static os_reg_list_t os_nif_list_net_dev[] =
    {
        OS_REG_LIST_ENTRY(1, "^[\t ]*([-a-zA-Z0-9]+):"),
        OS_REG_LIST_END(0)
    };

    /* Initialize the list */
    ds_list_init(list, struct os_nif_list_entry, le_node);

    fnetdev = fopen("/proc/net/dev", "r");
    if (fnetdev == NULL)
    {
        LOG(ERR, "os_nif_list_get: Error opening: /proc/net/dev");
        goto error;
    }

    while (fgets(buf, sizeof(buf), fnetdev) != NULL)
    {
        int         match;
        regmatch_t  rm[2];

        match = os_reg_list_match(os_nif_list_net_dev, buf, rm, ARRAY_LEN(rm));
        switch (match)
        {
            case 1:
                n = malloc(sizeof(struct os_nif_list_entry));
                if (n == NULL)
                {
                    LOG(ERR, "Error allocating space for new nif entry.");
                    goto error;
                }

                os_reg_match_cpy(n->le_ifname, sizeof(n->le_ifname), buf, rm[1]);

                ds_list_insert_head(list, n);

                break;

            case 0:
                break;
        }
    }

    retval = true;

error:
    if (fnetdev != NULL)
    {
        fclose(fnetdev);
    }

    if (retval != true)
    {
        os_nif_list_free(list);
    }

    return retval;
}

/**
 * Free a list that was returned by os_nif_list_get()
 */
void os_nif_list_free(ds_list_t* list)
{
    struct os_nif_list_entry*   n;
    ds_list_iter_t              iter;

    for (n = ds_list_ifirst(&iter, list);
         n != NULL;
         n = ds_list_inext(&iter))
    {
        ds_list_iremove(&iter);
        free(n);
    }
}

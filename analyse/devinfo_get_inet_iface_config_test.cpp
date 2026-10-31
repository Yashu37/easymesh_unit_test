/*
 * TEST RUNNER: devinfo_get_inet_iface_config_test
 *
 * Two caller-owned buffers are poisoned here:
 *   - input  if_name : poison the tail past its terminator (over-read guard)
 *   - output config  : placed inside a larger backing buffer; everything
 *                      past sizeof(config) is poisoned, so any write beyond
 *                      the struct (e.g. a bad STRSCPY) aborts.
 * The internal *_cached[64] arrays are auto-guarded by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool devinfo_get_inet_iface_config(const char *if_name, devinfo_inet_iface_config_t *config);

/* backing buffer so we can poison memory right after the config struct */
static unsigned char cfg_backing[sizeof(devinfo_inet_iface_config_t) + 64];

int test_devinfo_cfg(const devinfo_cfg_test_case_t *tc)
{
    devinfo_inet_iface_config_t *config = (devinfo_inet_iface_config_t *)cfg_backing;
    memset(cfg_backing, 0, sizeof(cfg_backing));

    /* poison everything past the struct (output over-write guard) */
    __asan_poison_memory_region(cfg_backing + sizeof(devinfo_inet_iface_config_t),
                                sizeof(cfg_backing) - sizeof(devinfo_inet_iface_config_t));
    /* poison the input if_name tail (over-read guard) */
    __asan_poison_memory_region(&dgi_ifname[dgi_ifname_len + 1],
                                sizeof(dgi_ifname) - (dgi_ifname_len + 1));

    bool ret = devinfo_get_inet_iface_config(dgi_ifname, config);

    __asan_unpoison_memory_region(&dgi_ifname[dgi_ifname_len + 1],
                                  sizeof(dgi_ifname) - (dgi_ifname_len + 1));

    if (ret)
        printf("    ret=1 inet_addr=\"%s\" mac_str=\"%s\"\n", config->inet_addr, config->mac_str);
    else
        printf("    ret=0\n");

    __asan_unpoison_memory_region(cfg_backing + sizeof(devinfo_inet_iface_config_t),
                                  sizeof(cfg_backing) - sizeof(devinfo_inet_iface_config_t));
    return ret ? 1 : 0;
}

void run_all_tests_devinfo_cfg(void)
{
    for (int i = 0; devinfo_cfg_suite[i].test_name != NULL; i++) {
        devinfo_cfg_test_case_t *test = &devinfo_cfg_suite[i];

        printf("--- Running Test: %s  if_name=\"%s\" ---\n", test->test_name, test->if_name);

        construct_devinfo_cfg_input(test);

        int got = test_devinfo_cfg(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}

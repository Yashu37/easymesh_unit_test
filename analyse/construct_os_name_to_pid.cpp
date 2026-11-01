/*
 * TEST CASES / CONSTRUCTOR: construct_os_name_to_pid
 *
 * os_name_to_pid(name) scans /proc/<pid>/comm for a process whose comm
 * matches name. Cases: our own process name (should be found), a name that
 * does not exist, an empty name, and a 255-char name
 * (longest that fits onp_name; comm is at most 15 chars). proc_name is runner-owned (poisoned
 * tail). Our binary's comm is read from /proc/self/comm at setup.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        onp_name[256];
size_t      onp_name_len;
char        onp_self_comm[64];   /* this process's comm (for the find-self case) */
const char *onp_case_name;

os_name_pid_test_case_t os_name_pid_suite[] = {
    /* name            which           expect_found */
    { "find_self",     ONP_SELF,        1 },
    { "not_found",     ONP_LITERAL,     0 },   /* uses "no_such_proc_xyz" */
    { "empty_name",    ONP_EMPTY,       0 },
    { "long_name_255", ONP_LONG,        0 },   /* 255 'A's, fills onp_name */

    { NULL, 0, 0 }  /* sentinel */
};

void construct_os_name_pid_input(const os_name_pid_test_case_t *tc)
{
    onp_case_name = tc->test_name;

    /* read our own comm once */
    if (onp_self_comm[0] == '\0') {
        FILE *f = fopen("/proc/self/comm", "r");
        if (f) {
            if (fgets(onp_self_comm, sizeof(onp_self_comm), f)) {
                char *nl = strchr(onp_self_comm, '\n');
                if (nl) *nl = '\0';
            }
            fclose(f);
        }
    }

    memset(onp_name, 0, sizeof(onp_name));
    if (tc->which == ONP_SELF)        snprintf(onp_name, sizeof(onp_name), "%s", onp_self_comm);
    else if (tc->which == ONP_LITERAL) snprintf(onp_name, sizeof(onp_name), "no_such_proc_xyz");
    else if (tc->which == ONP_LONG)    memset(onp_name, 'A', sizeof(onp_name) - 1);
    else                               onp_name[0] = '\0';   /* empty */

    onp_name_len = strlen(onp_name);
}

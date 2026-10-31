/*
 * TEST CASES / CONSTRUCTOR: construct_os_pid_from_file
 *
 * os_pid_from_file(path) reads the first line of a file into buf[64], parses
 * a pid with atol, and returns it if kill(pid,0) says it is alive. Cases
 * cover: a live pid (our own), a long line (> 64 bytes) to stress buf, a
 * dead pid, zero, non-numeric, empty, and a missing file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        ospid_path[256];
const char *ospid_case_name;

os_pid_test_case_t os_pid_suite[] = {
    /* name            kind            expect_nonzero */
    { "live_pid",      OSPID_LIVE,     1 },
    { "long_line",     OSPID_LONGLINE, 1 },   /* valid pid + >64 bytes of junk */
    { "dead_pid",      OSPID_DEAD,     0 },
    { "zero",          OSPID_ZERO,     0 },
    { "non_numeric",   OSPID_NONNUM,   0 },
    { "empty_file",    OSPID_EMPTY,    0 },
    { "missing_file",  OSPID_MISSING,  0 },

    { NULL, 0, 0 }  /* sentinel */
};

void construct_os_pid_from_file_input(const os_pid_test_case_t *tc)
{
    ospid_case_name = tc->test_name;
    snprintf(ospid_path, sizeof(ospid_path), "/tmp/ospid_%s.pid", tc->test_name);
    remove(ospid_path);

    FILE *f;
    switch (tc->kind) {
        case OSPID_LIVE:
            f = fopen(ospid_path, "w");
            if (f) { fprintf(f, "%ld\n", (long)getpid()); fclose(f); }
            break;

        case OSPID_LONGLINE: {
            /* our live pid followed by >64 bytes of 'A' on the same line */
            f = fopen(ospid_path, "w");
            if (f) {
                fprintf(f, "%ld", (long)getpid());
                for (int i = 0; i < 200; i++) fputc('A', f);
                fputc('\n', f);
                fclose(f);
            }
            break;
        }

        case OSPID_DEAD: {
            pid_t pid = fork();
            if (pid == 0) _exit(0);
            int st; waitpid(pid, &st, 0);     /* reap -> pid now dead */
            f = fopen(ospid_path, "w");
            if (f) { fprintf(f, "%ld\n", (long)pid); fclose(f); }
            break;
        }

        case OSPID_ZERO:
            f = fopen(ospid_path, "w"); if (f) { fputs("0\n", f); fclose(f); }
            break;

        case OSPID_NONNUM:
            f = fopen(ospid_path, "w"); if (f) { fputs("not_a_pid\n", f); fclose(f); }
            break;

        case OSPID_EMPTY:
            f = fopen(ospid_path, "w"); if (f) fclose(f);   /* empty file */
            break;

        case OSPID_MISSING:
        default:
            /* leave the file absent */
            break;
    }
}

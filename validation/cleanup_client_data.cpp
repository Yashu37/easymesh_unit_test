/*
 * HANDLER: cleanup_client_data
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:27-35
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_CCD_FIX 0 it is the VERBATIM original;
 * with RDK_CCD_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only:
 *  - hal_ipc_processor_desc_t is the scaffold struct from common.h (only its
 *    sizeof matters for the comparison).
 *  - free() is redirected to a counting stub (hcc_stub_free) that records the
 *    pointer and then calls the real free, so a double / invalid free is still
 *    reported by ASan.
 *  - the function is static in the original: cleanup_client_data_entry()
 *    forwards to it so the runner can call it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_CCD_FIX  1

#define free hcc_stub_free

/* --- copied from hal_ipc_processors.c:27 --- */
//--------------------------------------------------------------------------------------------------
static void cleanup_client_data(unsigned char **client_scratch_buf, int client_data_len)
{
#if RDK_CCD_FIX
    /* FIX 1: the pointer-to-pointer itself was dereferenced unchecked. */
    if (client_scratch_buf == NULL) {
        return;
    }
#endif
    if (client_data_len > sizeof(hal_ipc_processor_desc_t)) {
        if (*client_scratch_buf != NULL) {
            free(*client_scratch_buf);
            *client_scratch_buf = NULL;
        }
    }
}

#undef free
void cleanup_client_data_entry(unsigned char **p, int len) { cleanup_client_data(p, len); }

/*
 * HANDLER: cleanup_client_data
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:27-35 (~/Desktop/G/rdk-wifi-hal).  This file
 * holds ONLY THE FIXED code: it carries FIX 1 below.
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


#define free hcc_stub_free

/* --- copied from hal_ipc_processors.c:27 --- */
//--------------------------------------------------------------------------------------------------
static void cleanup_client_data(unsigned char **client_scratch_buf, int client_data_len)
{
    /* FIX 1: the pointer-to-pointer itself was dereferenced unchecked. */
    if (client_scratch_buf == NULL) {
        return;
    }
    if (client_data_len > sizeof(hal_ipc_processor_desc_t)) {
        if (*client_scratch_buf != NULL) {
            free(*client_scratch_buf);
            *client_scratch_buf = NULL;
        }
    }
}

#undef free
void cleanup_client_data_entry(unsigned char **p, int len) { cleanup_client_data(p, len); }

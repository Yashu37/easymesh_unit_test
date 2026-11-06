/*
 * HANDLER: cleanup_desc_scratch_buf
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:38-42 (~/Desktop/G/rdk-wifi-hal).  This file
 * holds ONLY THE FIXED code: it carries FIX 1 below.
 *
 * Scaffolding only: hal_ipc_processor_desc_t is the scaffold struct from
 * common.h (real leading fields + scratch_buf / scratch_buf_size).  The
 * function is static in the original: cleanup_desc_scratch_buf_entry()
 * forwards to it so the runner can call it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"


/* --- copied from hal_ipc_processors.c:38 --- */
static void cleanup_desc_scratch_buf(struct hal_ipc_processor_desc *desc)
{
    /* FIX 1: desc was dereferenced unchecked. */
    if (desc == NULL) {
        return;
    }
    desc->scratch_buf_size = 0;
    desc->scratch_buf = NULL;
}

void cleanup_desc_scratch_buf_entry(hal_ipc_processor_desc_t *d) { cleanup_desc_scratch_buf(d); }

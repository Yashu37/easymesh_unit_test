/*
 * HANDLER: ds_tree_node_str
 *
 * Function copied VERBATIM from OneWifi lib/ds/ds_tree.c:525. No fixes.
 * This is the canonical (non-static) copy; ds_tree_check_r.cpp and
 * ds_tree_graphviz_r.cpp keep their own file-local static copies.
 *
 * It returns root->ot_str_fn(node) when a string function is set; otherwise
 * it formats node->otn_key into a static node_ptr[22] with snprintf("%p").
 * A pointer prints as at most "0x" + 16 hex = 18 chars + NUL = 19 <= 22, so
 * node_ptr cannot overflow. The input node/root are caller-owned (poisoned
 * by the runner); node_ptr is internal and auto-guarded by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/ds/ds_tree.c:525 --- */
char *ds_tree_node_str(ds_tree_t *root, ds_tree_node_t *node)
{
    if (root->ot_str_fn != NULL)
    {
        return root->ot_str_fn(node);
    }

    static char node_ptr[22];

    snprintf(node_ptr, sizeof(node_ptr), "%p", node->otn_key);

    return node_ptr;
}

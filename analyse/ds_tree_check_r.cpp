/*
 * HANDLER: ds_tree_check_r
 *
 * Function copied VERBATIM from OneWifi lib/ds/ds_tree.c, together with its
 * helper ds_tree_node_str (verbatim, kept static here so the dedicated
 * ds_tree_node_str harness can own the non-static copy). No fixes.
 *
 * ds_tree_check_r validates a red-black tree recursively. Its only array,
 * rc[2], and the node's otn_child[2] are fixed size 2 indexed by 0/1 (loop
 * bound c < 2), so no array out-of-bounds is possible by construction. The
 * helper's node_ptr[22] is a bounded snprintf("%p") buffer. There is no
 * caller-owned linear buffer to __asan_poison (the input is a pointer-based
 * tree); ASan auto-guards the internal arrays.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/ds/ds_tree.c --- */
#define OTN_PROP_RED     1
#define OTN_PROP_BLACK   0
#define OTN_IS_RED(x)    ( (x) != NULL && ((x)->otn_prop == OTN_PROP_RED) )

static char *ds_tree_node_str(ds_tree_t *root, ds_tree_node_t *node)
{
    if (root->ot_str_fn != NULL)
    {
        return root->ot_str_fn(node);
    }

    static char node_ptr[22];

    snprintf(node_ptr, sizeof(node_ptr), "%p", node->otn_key);

    return node_ptr;
}

int ds_tree_check_r(ds_tree_t *root, ds_tree_node_t *node)
{
    int rc[2] = { 0, 0 };

    int c;
    /* Check if both children's parents point to node */
    for (c = 0; c < 2; c++)
    {
        if (node->otn_child[c] != NULL)
        {
            if (node->otn_child[c]->otn_parent != node) return -1;

            rc[c] = ds_tree_check_r(root, node->otn_child[c]);

            if (rc[c] < 0) return -1;
        }
    }

    /* Black violation: each path in the subtrees must have the same number of black nodes */
    if (rc[0] != rc[1])
    {
        printf("Black violation at node %s\n", ds_tree_node_str(root, node));
        return -1;
    }

    /* Red-violation */
    if (!OTN_IS_RED(node))
    {
        return rc[0] + 1;
    }

    if (OTN_IS_RED(node->otn_child[0]))
    {
        printf("Red violation at node: %s\n", ds_tree_node_str(root, node));
        return -1;
    }

    if (OTN_IS_RED(node->otn_child[1]))
    {
        printf("Red violation at node: %s\n", ds_tree_node_str(root, node));
        return -1;
    }

    return rc[0];
}

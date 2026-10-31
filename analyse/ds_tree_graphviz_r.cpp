/*
 * HANDLER: ds_tree_graphviz_r
 *
 * Function copied VERBATIM from OneWifi lib/ds/ds_tree.c, with its helper
 * ds_tree_node_str (verbatim, kept static here; the dedicated
 * ds_tree_node_str harness owns the non-static copy). No fixes.
 *
 * snode[64]/schild[64] are filled by bounded snprintf, children indexed
 * c < 2. There is no caller-owned linear buffer (input is a pointer tree +
 * a FILE*); ASan auto-guards the internal arrays and the helper's
 * node_ptr[22].
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
#define DS_TREE_NODE_STR_SZ 64

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

void ds_tree_graphviz_r(ds_tree_t *root, FILE *fdot, ds_tree_node_t *node)
{
    char snode[DS_TREE_NODE_STR_SZ];
    char schild[DS_TREE_NODE_STR_SZ];
    int c;

    snprintf(snode, sizeof(snode), "%s", ds_tree_node_str(root, node));

    fprintf(fdot, "%s [fillcolor=%s];\n", snode, OTN_IS_RED(node) ? "red" : "black");


    for (c = 0; c < 2; c++)
    {
        if (node->otn_child[c] != NULL)
        {
            snprintf(schild, sizeof(schild), "%s", ds_tree_node_str(root, node->otn_child[c]));
            /* Recurs down */
            ds_tree_graphviz_r(root, fdot, node->otn_child[c]);
        }
        else
        {
            static int nullcnt = 0;
            nullcnt++;

            snprintf(schild, sizeof(schild), "null%d", nullcnt);

            fprintf(fdot, "null%d [shape=point];\n", nullcnt);
        }

        fprintf(fdot, "%s -> %s [color=%s, arrowhead=%s];\n", snode, schild, c == 0 ? "purple" : "green", c == 0 ? "rnormal" : "lnormal");
    }

}

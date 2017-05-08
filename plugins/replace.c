#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>

#include "include/common.h"
#include "include/plugin.h"

typedef struct {
    unsigned char target;
    unsigned char replace;
} replace_t;

static int init(plugin_t* self, int argc, char* argv[])
{
    int c;
    int ret = 0;
    replace_t* priv = NULL;

    priv = malloc(sizeof(replace_t));
    if (!priv) {
        PRINT_ERR("alloc error\n");
        ret = -1;
        goto out;
    }

    memset(priv, 0, sizeof(*priv));

    while ((c = getopt(argc, argv, "t:r:")) != -1) {
        switch (c) {
            case 't':
                priv->target = atoi(optarg);
                break;
            case 'r':
                priv->replace = atoi(optarg);
                break;
            case '?':
                if (optopt == 'r' || optopt == 't') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
                }
                ret = -1;
                goto out;
        }
    }

    self->priv = (void*)priv;

out:
    if (ret != 0) {
        if (priv) {
            free(priv);
        }
    }
    return ret;
}

static void destroy(plugin_t* self)
{
    replace_t* priv = (replace_t*)self->priv;

    free(priv);
}

static void callback(plugin_t* self, unsigned char* buf, uint16_t* buf_len)
{
    int i;
    replace_t* priv = (replace_t*)self->priv;

    for (i = 0; i < *buf_len; ++i) {
        if (buf[i] == priv->target) {
            buf[i] = priv->replace;
        }
    }
}

plugin_t replace_plugin = {
    .name = "replace",
    .priv = NULL,
    .type = PLUGIN_UDP | PLUGIN_TCP | PLUGIN_IPV4,
    .init = init,
    .destroy = destroy,
    .callback = callback
};

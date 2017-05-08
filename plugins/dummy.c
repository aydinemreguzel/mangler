#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

#include "include/common.h"
#include "include/plugin.h"

typedef struct {
    int dummy;
} dummy_t;

static int init(plugin_t* self, int argc, char* argv[])
{
    int c;
    int ret = 0;
    dummy_t* priv = NULL;

    priv = malloc(sizeof(dummy_t));
    if (!priv) {
        PRINT_ERR("alloc error\n");
        ret = -1;
        goto out;
    }

    memset(priv, 0, sizeof(*priv));

    while ((c = getopt(argc, argv, "d:")) != -1) {
        switch (c) {
            case 'd':
                priv->dummy = atoi(optarg);
                break;
            case '?':
                if (optopt == 'd') {
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
    dummy_t* priv = (dummy_t*)self->priv;

    free(priv);
}

static void callback(plugin_t* self, unsigned char* buf, uint16_t* buf_len)
{
    dummy_t* priv = (dummy_t*)self->priv;
    (void)priv;
}

plugin_t dummy_plugin = {
    .name = "dummy",
    .type = PLUGIN_UDP | PLUGIN_TCP | PLUGIN_IPV4,
    .priv = NULL,
    .init = init,
    .destroy = destroy,
    .callback = callback
};

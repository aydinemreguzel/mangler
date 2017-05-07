#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "include/common.h"
#include "include/plugin.h"

typedef struct {
    char* str;
} appendstr_t;

static int init(plugin_t* self, int argc, char* argv[])
{
    int c;
    int ret = 0;
    appendstr_t* priv = NULL;

    priv = malloc(sizeof(appendstr_t));
    if (!priv) {
        PRINT_ERR("alloc error\n");
        ret = -1;
        goto out;
    }

    memset(priv, 0, sizeof(*priv));

    while ((c = getopt(argc, argv, "s:")) != -1) {
        switch (c) {
            case 's':
                if (!priv->str) {
                    priv->str = strdup(optarg);
                    if (!priv->str) {
                        PRINT_ERR("alloc error\n");
                        ret = -1;
                        goto out;
                    }
                }
                break;
            case '?':
                if (optopt == 's') {
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

    if (!priv->str) {
        PRINT_ERR("No string entered\n");
        ret = -1;
        goto out;
    }

    self->priv = (void*)priv;

out:
    if (ret != 0) {
        if (priv) {
            if (priv->str) {
                free(priv->str);
            }
            free(priv);
        }
    }
    return ret;
}

static void destroy(plugin_t* self)
{
    appendstr_t* priv = (appendstr_t*)self->priv;

    free(priv->str);
    free(priv);
}

static void callback(plugin_t* self, char* buf, uint16_t* buf_len)
{
    appendstr_t* priv = (appendstr_t*)self->priv;

    strcpy(&buf[*buf_len], priv->str);

    *buf_len += strlen(priv->str);
}

plugin_t appendstr_plugin = {
    .name = "appendstr",
    .priv = NULL,
    .type = PLUGIN_UDP | PLUGIN_IPV4,
    .init = init,
    .destroy = destroy,
    .callback = callback
};

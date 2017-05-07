#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>

#include <syscall.h>
#include <linux/random.h>

#include "include/common.h"
#include "include/plugin.h"

typedef struct {
    float flip_chance;
} flipbits_t;

static void __getrandom(char* buf, size_t buf_len)
{
    syscall(SYS_getrandom, buf, buf_len, 0);
}

static bool chance(float f)
{
    uint16_t rnd;
    float rnd_f;

    __getrandom((char*) &rnd, sizeof(rnd));
    rnd_f = ((float) rnd) / ((float) 0xffff);

    return (f >= rnd_f);
}

static int init(plugin_t* self, int argc, char* argv[])
{
    int c;
    int rc;
    int ret = 0;
    flipbits_t* priv = NULL;

    priv = malloc(sizeof(flipbits_t));
    if (!priv) {
        PRINT_ERR("alloc error\n");
        ret = -1;
        goto out;
    }

    memset(priv, 0, sizeof(*priv));

    while ((c = getopt(argc, argv, "c:")) != -1) {
        switch (c) {
            case 'c':
                rc = sscanf(optarg, "%f", &priv->flip_chance);
                if (rc != 1 || priv->flip_chance < 0.0 || priv->flip_chance > 1.0) {
                    PRINT_ERR("Invalid value entered\n");
                    ret = -1;
                    goto out;
                }
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
    flipbits_t* priv = (flipbits_t*)self->priv;

    free(priv);
}

static void callback(plugin_t* self, char* buf, uint16_t* buf_len)
{
    int i;
    int bitcnt = *buf_len * 8;
    flipbits_t* priv = (flipbits_t*)self->priv;

    /* FIXME: this is very inefficient */
    for (i = 0; i < bitcnt; ++i) {
        if (chance(priv->flip_chance)) {
            char byte = buf[i / 8];
            byte ^= 1 << (i % 8);
            buf[i / 8] = byte;
        }
    }
}

plugin_t flipbits_plugin = {
    .name = "flipbits",
    .type = PLUGIN_UDP | PLUGIN_TCP | PLUGIN_IPV4,
    .priv = NULL,
    .init = init,
    .destroy = destroy,
    .callback = callback
};

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "include/plugin.h"

extern plugin_t dummy_plugin;
extern plugin_t appendstr_plugin;
extern plugin_t random_plugin;
extern plugin_t replace_plugin;
extern plugin_t flipbits_plugin;

plugin_t* mangle_plugins[] = {
    &dummy_plugin,
    &appendstr_plugin,
    &random_plugin,
    &replace_plugin,
    &flipbits_plugin,
    NULL,
};

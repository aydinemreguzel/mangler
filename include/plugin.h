#ifndef __PLUGIN_H__
#define __PLUGIN_H__

typedef enum {
    PLUGIN_UNKNOWN = 0x0,
    PLUGIN_UDP = 0x1,
    PLUGIN_TCP = 0x2,
    PLUGIN_IPV4 = 0x4
} plug_type_e;

struct plugin_s;
typedef struct plugin_s plugin_t;

typedef int (*plug_init_t)(plugin_t* self, int argc, char* argv[]);
typedef void (*plug_destroy_t)(plugin_t* self);
typedef void (*plug_cb_t)(plugin_t* self, unsigned char* buf, uint16_t* buf_len);

struct plugin_s {
    const char* name;
    int type;
    void* priv;
    plug_init_t init;
    plug_destroy_t destroy;
    plug_cb_t callback;
};

#endif /* ifndef __PLUGIN_H__ */

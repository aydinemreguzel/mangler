#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "keyval_proto.h"

typedef struct {
    const char* key;
    const char* val;
} key_val_t;

static key_val_t table[] = {
    {.key = "potato", .val = "tomato" },
    {.key = "cat", .val = "dog" },
    {.key = "red", .val = "blue" },
    {.key = NULL, .val = NULL }
};

static const char* get_val(const char* key)
{
    int idx = 0;
    while (table[idx].key != NULL) {
        if (!strcmp(key, table[idx].key)) {
            return table[idx].val;
        }
        idx++;
    }

    return NULL;
}

size_t prep_req(keyval_proto_req_t* req, const char* key)
{
    size_t len;
    req->hdr.type = MSG_REQUEST;
    strcpy(req->key, key);
    req->key[strlen(key)] = '\0';
    req->key_len = htons(strlen(key) + 1);

    len = sizeof(*req) + strlen(key) + 1;
    return len;
}

size_t prep_resp(keyval_proto_resp_t* resp, const char* val)
{
    size_t len;
    resp->hdr.type = MSG_RESPONSE;
    if (val != NULL) {
        strcpy(resp->val, val);
        resp->val[strlen(val)] = '\0';
        resp->val_len = htons(strlen(val) + 1);
        resp->result = RES_SUCCESS;
        len = sizeof(*resp) + strlen(val) + 1;
    } else {
        resp->result = RES_NOTFOUND;
        len = sizeof(*resp);
    }

    return len;
}

int handle_msg(int sock, uint8_t* in_buf, struct sockaddr_in* other_addr, socklen_t sock_len)
{
    int ret = 0;
    uint8_t out_buf[512];

    /* parse the header first */
    const keyval_proto_hdr_t* header = (const keyval_proto_hdr_t*)in_buf;

    switch (header->type) {
        case MSG_REQUEST: {
            const keyval_proto_req_t* req = (keyval_proto_req_t*)in_buf;
            char key[512];
            memcpy(key, req->key, ntohs(req->key_len));
            printf("Req Key: '%s'\n", key);

            {
                keyval_proto_resp_t* resp = (keyval_proto_resp_t*)out_buf;
                const char* val = get_val(key);
                size_t out_len = prep_resp(resp, val);

                /* send response */
                sendto(sock, out_buf, out_len, 0, (struct sockaddr*)other_addr, sock_len);
            }
            break;
        }
        case MSG_RESPONSE: {
            const keyval_proto_resp_t* resp = (keyval_proto_resp_t*)in_buf;
            if (resp->result == RES_SUCCESS) {
                char val[512];
                memcpy(val, resp->val, ntohs(resp->val_len));
                printf("Val: '%s'\n", val);
            } else {
                printf("Key not found\n");
            }
            break;
        }
        default:
            fprintf(stderr, "Unknown type received\n");
            ret = -1;
            goto out;
    }

out:
    return ret;
}

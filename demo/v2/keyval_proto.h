#ifndef __KEYVAL_PROTO_H__
#define __KEYVAL_PROTO_H__

#define KEYLEN 64

typedef enum {
	MSG_REQUEST = 0,
	MSG_RESPONSE,
} keyval_msg_type_e;

typedef enum {
	RES_SUCCESS = 0,
	RES_NOTFOUND,
} keyval_res_e;

typedef struct {
	uint8_t type;
	uint32_t crc;
} __attribute__((__packed__)) keyval_proto_hdr_t;

typedef struct {
	keyval_proto_hdr_t hdr;
	uint16_t key_len;
	uint8_t key[0];
} __attribute__((__packed__)) keyval_proto_req_t;

typedef struct {
	keyval_proto_hdr_t hdr;
	uint8_t result;
	uint16_t val_len;
	uint8_t val[0];
} __attribute__((__packed__)) keyval_proto_resp_t;

int handle_msg(int sock, uint8_t* in_buf, ssize_t len, struct sockaddr_in* other_addr, socklen_t sock_len);
size_t prep_req(keyval_proto_req_t* req, const char* key);
size_t prep_resp(keyval_proto_resp_t* resp, const char* val);

#endif /* ifndef __KEYVAL_PROTO_H__ */

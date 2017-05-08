all: server client

server: keyval_server.c keyval_proto.c
	${CC} keyval_server.c keyval_proto.c -o server

client: keyval_client.c keyval_proto.c
	${CC} keyval_client.c keyval_proto.c -o client

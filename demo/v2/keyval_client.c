#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "keyval_proto.h"

#define BUFSIZE 512

int udp_sock()
{
    int fd = -1;
    int rc = 0;

    rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rc == -1) {
        goto out;
    }

    fd = rc;
    rc = 0;

out:
    if (rc != 0) {
        if (fd -= -1) {
            close(fd);
            fd = -1;
        }
    }
    return fd;
}

int listen_loop(int sock, const char* hostname)
{
    int ret = 0;
    int rc;
    struct sockaddr_in remote;
    struct hostent* hp;

    hp = gethostbyname(hostname);
    if (!hp) {
        goto out;
    }

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(1234);
    memcpy(&remote.sin_addr.s_addr, hp->h_addr_list[0], 4);

    for (;;) {
        char key[128];
        uint8_t buf[BUFSIZE] = { 0 };
        keyval_proto_req_t* req;
        struct sockaddr_in other_addr;
        socklen_t addr_len = sizeof(other_addr);
        req = (keyval_proto_req_t*)buf;

        scanf("%s", key);
        size_t len = prep_req(req, key);

        rc = sendto(sock, buf, len, 0, (struct sockaddr*)&remote, sizeof(remote));
        if (rc == -1) {
            printf("err\n");
            ret = -1;
            goto out;
        }

        rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&other_addr, &addr_len);
        if (rc == -1) {
            printf("err\n");
            ret = -1;
            goto out;
        }

        handle_msg(sock, buf, rc, &remote, sizeof(remote));
    }

out:
    return ret;
}

int main(int argc, char* argv[])
{
    int rc;
    int ret = 0;
    int sock = udp_sock();

    if (argc < 2) {
        printf("no hostname given\n");
        ret = 1;
        goto out;
    }

    if (sock == -1) {
        printf("sock err\n");
        ret = 1;
        goto out;
    }

    rc = listen_loop(sock, argv[1]);
    if (rc == -1) {
        ret = 1;
        goto out;
    }

out:
    if (sock != -1) {
        close(sock);
    }
    return ret;
}

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

int udp_sock(int port)
{
    int fd = -1;
    int rc = 0;
    struct sockaddr_in addr_mine;

    rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rc == -1) {
        goto out;
    }

    fd = rc;
    rc = 0;

    memset((char*)&addr_mine, 0, sizeof(addr_mine));
    addr_mine.sin_family = AF_INET;
    addr_mine.sin_port = htons(port);
    addr_mine.sin_addr.s_addr = htonl(INADDR_ANY);
    rc = bind(fd, (const struct sockaddr*)&addr_mine, sizeof(addr_mine));
    if (rc == -1) {
        goto out;
    }

out:
    if (rc != 0) {
        if (fd -= -1) {
            close(fd);
            fd = -1;
        }
    }
    return fd;
}

int listen_loop(int sock)
{
    int ret = 0;
    int rc;

    for (;;) {
        uint8_t buf[BUFSIZE] = { 0 };
        struct sockaddr_in other_addr;

        socklen_t addr_len = sizeof(other_addr);

        rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&other_addr, &addr_len);
        if (rc == -1) {
            ret = -1;
            goto out;
        }

        handle_msg(sock, buf, rc, &other_addr, addr_len);
    }

out:
    return ret;
}

int main(int argc, char* argv[])
{
    int rc;
    int ret = 0;
    int sock = udp_sock(1234);

    if (sock == -1) {
        ret = 1;
        goto out;
    }

    rc = listen_loop(sock);
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

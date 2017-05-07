#ifndef __COMMON_H__
#define __COMMON_H__

#define PRINT(fmt, ...) printf("%s:%s(%d): " fmt, __FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define PRINT_ERR(fmt, ...) fprintf(stderr, "%s:%s(%d): " fmt, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#define IP_FMT "%d.%d.%d.%d"

#define IPADDR(addr)                \
    ((unsigned char*)&addr)[0],     \
        ((unsigned char*)&addr)[1], \
        ((unsigned char*)&addr)[2], \
        ((unsigned char*)&addr)[3]

#endif /* ifndef __COMMON_H__ */

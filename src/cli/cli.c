#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))
					   
struct msg_hdr {
    char path[32];
    uint8_t flag;
    uint8_t cmd;
    uint16_t len;
    uint8_t data[0];
};

#define NEIGH_TYPE_LOCAL        1
#define NEIGH_TYPE_REACHABLE    2
#define NEIGH_TYPE_UNRESOLVED   3

enum {
    ROUTE_MSG_ADD_NEIGH,
    ROUTE_MSG_DEL_NEIGH,
    ROUTE_MSG_ADD_NH,
    ROUTE_MSG_DEL_NH,
    ROUTE_MSG_ADD_NH6,
    ROUTE_MSG_DEL_NH6,
};

struct route_add {
    uint32_t ip;
    uint8_t depth;
    uint32_t nh_ip;
    uint32_t nh_iface;
};

struct route_del {
    uint32_t ip;
    uint8_t depth;
};

struct route6_add {
    uint8_t ip[16];
    uint8_t depth;
    uint8_t nh_ip[16];
    uint32_t nh_iface;
};

struct route6_del {
    uint8_t ip[16];
    uint8_t depth;
};

struct arp_add {
    uint32_t nh_ip;
    uint32_t nh_iface;
    uint16_t type;
    uint8_t nh_arp[6];
};

struct arp_del {
    uint32_t nh_ip;
    uint32_t nh_iface;
};

void print_route_cmd()
{
    printf("ROUTE_MSG_ADD_NEIGH: %d\n", ROUTE_MSG_ADD_NEIGH);
    printf("ROUTE_MSG_DEL_NEIGH: %d\n", ROUTE_MSG_DEL_NEIGH);
    printf("ROUTE_MSG_ADD_NH: %d\n", ROUTE_MSG_ADD_NH);
    printf("ROUTE_MSG_DEL_NH: %d\n", ROUTE_MSG_DEL_NH);
    printf("ROUTE_MSG_ADD_NH6: %d\n", ROUTE_MSG_ADD_NH6);
    printf("ROUTE_MSG_DEL_NH6: %d\n", ROUTE_MSG_DEL_NH6);
}

int assemble_data(char *data)
{
    int length;
    struct msg_hdr *req;

    req = (struct msg_hdr *)data;
    
    length = sizeof(struct msg_hdr);

    printf("dest module\n");
    scanf("%s", req->path);

    if (strcmp(req->path, "route") == 0) {
        print_route_cmd();
        scanf("%d", &req->cmd);

        switch (req->cmd) {
        case ROUTE_MSG_ADD_NEIGH:
            {
                struct arp_add *add = (struct arp_add *)req->data;
                
                req->len = sizeof(struct arp_add);
                length += sizeof(struct arp_add);

                add->nh_ip = htonl(IPv4(192,168,101,100));
                add->nh_iface = htonl(1);

                add->type = htons(NEIGH_TYPE_REACHABLE);
                add->nh_arp[0] = 0x00;
                add->nh_arp[1] = 0x01;
                add->nh_arp[2] = 0x02;
                add->nh_arp[3] = 0x03;
                add->nh_arp[4] = 0x04;
                add->nh_arp[5] = 0x05;
            }
            break;
            
        case ROUTE_MSG_ADD_NH:
            {
                struct route_add *rt_add = (struct route_add *)req->data;
                
                req->len = sizeof(struct route_add);
                length += sizeof(struct route_add);

                rt_add->ip = htonl(IPv4(0,0,0,0));
                rt_add->depth = 0;
                rt_add->nh_ip = htonl(IPv4(192,168,101,100));
                rt_add->nh_iface = htonl(1);
            }
            break;

        default:
            break;
        }
    }

    printf("assemble cmd %d length %d\n", req->cmd, length);

    return length;
}

int disassemble_data(char *data)
{
    struct msg_hdr *resp = (struct msg_hdr *)data;

    printf("rcv msg from %s cmd %d flag %x\n", resp->path, resp->cmd, resp->flag);

    return 0;
}

int main()
{
    int sockfd, length, ret;
    socklen_t sklen;
    char req[1024] = {0};
    struct sockaddr_in serveraddr;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("open socket failed\n");
        exit(1);
    }

    sklen = sizeof(struct sockaddr_in);

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(4567);
    inet_aton("127,0,0,1", &serveraddr.sin_addr.s_addr);

    while (1) {
        memset(req, 0, sizeof(req));
        length = assemble_data(req);

        ret = sendto(sockfd, req, length, 0, 
            (struct sockaddr *)&serveraddr, sklen);
        if (ret != length) {
            printf("send to failed\n");
            exit(1);
        }

        ret = recvfrom(sockfd, req, 1024, 0, (struct sockaddr *)&serveraddr, &sklen);
        disassemble_data(req);
    }
    
    return 0;
}


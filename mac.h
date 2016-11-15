#ifndef MAC_H
#define MAC_H

#include <stdio.h>
#include <cstring>
#include "pcap.h"

#define MAX_PACKET_LENGTH 4192

typedef struct {
    __uint8_t dst_addr[6];
    __uint8_t src_addr[6];
    __uint16_t ether_type;
    __uint8_t data[1500];
} __attribute((packed)) eth_frame;

static const __uint8_t radiotap_header[] = {
        0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- bitmap
        0x22,
        0x0,
        0x18, 0x00
};

/* Penumbra IEEE80211 header */

static const __uint8_t ieee80211_header[] = {
        0x08, 0x01, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, /* -- SRC -- */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* -- DST -- */
        0x10, 0x86,
};

typedef struct  {
    int m_nChannel;
    int m_nChannelFlags;
    int m_nRate;
    int m_nAntenna;
    int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

typedef struct {
    __uint32_t sequence_number;
    __uint16_t ether_type;
} __attribute__((packed)) wifi_packet_header_t;

void init_packet_header(__uint8_t* packet_buffer);

void inject_packet(__uint8_t* packet, ssize_t length, __uint8_t* packet_buffer, pcap_t* ppcap);

#endif //MAC_H
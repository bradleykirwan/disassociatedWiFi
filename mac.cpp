#include <cstdlib>
#include <linux/if_ether.h>
#include "mac.h"

void init_packet_header(__uint8_t* packet_buffer) {
    memcpy(packet_buffer, &radiotap_header, sizeof(radiotap_header));
    memcpy(packet_buffer + sizeof(radiotap_header), &ieee80211_header, sizeof(ieee80211_header));
}

void inject_packet(__uint8_t* packet, ssize_t length, __uint8_t* packet_buffer, pcap_t* ppcap) {
    eth_frame *frame = (eth_frame *) packet;

    __uint8_t *src_mac = packet_buffer + sizeof(radiotap_header) + 10;
    __uint8_t *dst_mac = src_mac + 6;

    memcpy(src_mac, frame->src_addr, ETH_ALEN);
    memcpy(dst_mac, frame->dst_addr, ETH_ALEN);

    char* data = (char *) (packet_buffer + sizeof(radiotap_header) + sizeof(ieee80211_header));

    wifi_packet_header_t *wifi_packet_header = (wifi_packet_header_t *) data;
    wifi_packet_header->sequence_number = 137;
    wifi_packet_header->ether_type = frame->ether_type;

    data += sizeof(wifi_packet_header_t);

    memcpy(data, frame->data, (size_t) length - 14);

    size_t total_length = sizeof(radiotap_header) + sizeof(ieee80211_header) + sizeof(wifi_packet_header_t) + length - 14;

    int num_transmitted_bytes = pcap_inject(ppcap, packet_buffer, total_length);
    if (num_transmitted_bytes != total_length) {
        pcap_perror(ppcap, (char *) "Trouble injecting packet");
    }
}
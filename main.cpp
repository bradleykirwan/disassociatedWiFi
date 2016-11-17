#include <iostream>

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <zconf.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "mac.h"
#include "radiotap.h"

#define DEFAULT_TAP_NAME "wi"

bool running = true;
__uint8_t packet_buffer[MAX_PACKET_LENGTH];
pcap_t * ppcap = NULL;
int ieee80211_header_length = 0;
eth_frame outgoing_eth_frame;
__uint8_t virtual_mac[ETH_ALEN];

int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    const char *clonedev = "/dev/net/tun";

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        return fd;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev) {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* try to create the device */
    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}

void process_received_packet(struct pcap_pkthdr* ppcap_packet_header, __uint8_t* payload, int tun_fd) {
    struct ieee80211_radiotap_iterator rti;
    PENUMBRA_RADIOTAP_DATA prd;

    __uint16_t header_len = (payload[2] + (payload[3] << 8));

    if (ppcap_packet_header->len < (header_len + ieee80211_header_length)) {
        return;
    }

    int bytes = ppcap_packet_header->len - (header_len + ieee80211_header_length);
    if (bytes < 0) {
        return;
    }

    if (ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *) payload, bytes) < 0) {
        return;
    }

    while ((ieee80211_radiotap_iterator_next(&rti)) == 0) {
        switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                prd.m_nRate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                prd.m_nChannel = le16_to_cpu(*((u16 *)rti.this_arg));
                prd.m_nChannelFlags = le16_to_cpu(*((__uint16_t *)(rti.this_arg + 2)));
                break;

            case IEEE80211_RADIOTAP_ANTENNA:
                prd.m_nAntenna = (*rti.this_arg) + 1;
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                prd.m_nRadiotapFlags = *rti.this_arg;
                break;
        }
    }

    payload += header_len;

    memcpy(outgoing_eth_frame.src_addr, payload + 10, 6);
    memcpy(outgoing_eth_frame.dst_addr, payload + 16, 6);

    payload += ieee80211_header_length;

    wifi_packet_header_t *wifi_packet_header = (wifi_packet_header_t *) payload;
    __uint8_t *data = payload + sizeof(wifi_packet_header_t);

    outgoing_eth_frame.ether_type = wifi_packet_header->ether_type;

    ssize_t payload_length = bytes - sizeof(wifi_packet_header_t);

    memcpy(outgoing_eth_frame.data, data, (size_t) payload_length);

    write(tun_fd, &outgoing_eth_frame, (size_t) (14 + payload_length));
}

void process_data(int tun_fd) {
    __uint8_t buffer[MAX_PACKET_LENGTH];
    memset(&buffer, 0, MAX_PACKET_LENGTH);
    ssize_t nread, retval;
    __uint8_t* payload = buffer;
    struct pcap_pkthdr * ppcap_packet_header = NULL;

    while (running) {
        // Read incoming physical interface data
        retval = pcap_next_ex(ppcap, &ppcap_packet_header, (const u_char**)&payload);
        if (retval == 1) {
            // Received a packet
            process_received_packet(ppcap_packet_header, payload, tun_fd);
        }

        // Read incoming virtual interface data
        nread = read(tun_fd, buffer, MAX_PACKET_LENGTH);
        if (nread > 0) {
            inject_packet((__uint8_t *) &buffer, nread, packet_buffer, ppcap);
        }

        // Sleep for some time (be nice on CPUs)
        usleep(100);
    }
}

void set_non_blocking(int tun_fd) {
    int flags;

    if ((flags = fcntl(tun_fd, F_GETFL, 0)) < 0) {
        perror("Failed to get tap flags.");
        exit(1);
    }

    if (fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Failed to set tap to non-blocking.");
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    char tap_name[IFNAMSIZ], phy_name[IFNAMSIZ];
    tap_name[0] = 0;
    phy_name[0] = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && (i + 1 < argc)) {
            sprintf(phy_name, argv[i + 1]);
        } else if (strcmp(argv[i], "-n") == 0 & (i + 1 < argc)) {
            sprintf(tap_name, argv[i + 1]);
        }
    }

    // Make sure physical interface provided
    if (phy_name[0] == 0) {
        perror("No physical interface name provided.");
        exit(1);
    }

    // If tap name not set, use default name
    if (tap_name[0] == 0) {
        sprintf(tap_name, DEFAULT_TAP_NAME);
    }

    int tun_fd = tun_alloc(tap_name, IFF_TAP | IFF_NO_PI);

    if (tun_fd < 0){
        perror("Allocating interface.");
        exit(1);
    }

    if (ioctl(tun_fd, TUNSETPERSIST, 1) < 0){
        perror("Enabling TUNSETPERSIST.");
        exit(1);
    }

    struct ifreq buffer;
    ioctl(tun_fd, SIOCGIFHWADDR, &buffer);
    memcpy(virtual_mac, buffer.ifr_hwaddr.sa_data, ETH_ALEN);

    char szErrbuf[PCAP_ERRBUF_SIZE];
    szErrbuf[0] = '\0';
    ppcap = pcap_open_live(phy_name, 2048, 1, 5, szErrbuf);
    if (ppcap == NULL) {
        fprintf(stderr, "Unable to open interface %s in pcap: %s\n", phy_name, szErrbuf);
        exit(1);
    }

    int n_link_encap = pcap_datalink(ppcap);
    char * szProgram;
    struct bpf_program bpfprogram;

    switch (n_link_encap) {
        // TODO change szProgram to filter packets with destination: broadcast or unicast
        case DLT_PRISM_HEADER:
            printf("DLT_PRISM_HEADER Encap\n");
            ieee80211_header_length = 0x20; // ieee80211 comes after this
            szProgram = (char *) "radio[0x4a:4]==0x13223344";
            break;

        case DLT_IEEE802_11_RADIO:
            printf("DLT_IEEE802_11_RADIO Encap\n");
            ieee80211_header_length = 0x18; // ieee80211 comes after this
            char filter_buffer[1000];
            sprintf(filter_buffer, "(ether[0x10:4]==0x%02x%02x%02x%02x && ether[0x14:2]==0x%02x%02x)||(ether[0x10:4]==0xffffffff && ether[0x14:2]==0xffff)",
                    virtual_mac[0], virtual_mac[1], virtual_mac[2], virtual_mac[3], virtual_mac[4], virtual_mac[5]);
            szProgram = filter_buffer;

            break;

        default:
            perror("Unknown encapsulation used on physical interface!");
            exit(1);
    }

    if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
        puts(szProgram);
        puts(pcap_geterr(ppcap));
        return (1);
    } else {
        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            puts(szProgram);
            puts(pcap_geterr(ppcap));
        } else {
            printf("Listening for packets addressed to %02x:%02x:%02x:%02x:%02x:%02x\n",
                   virtual_mac[0], virtual_mac[1], virtual_mac[2], virtual_mac[3], virtual_mac[4], virtual_mac[5]);
        }
        pcap_freecode(&bpfprogram);
    }

    pcap_setnonblock(ppcap, 1, szErrbuf);

    init_packet_header(packet_buffer);

    set_non_blocking(tun_fd);
    process_data(tun_fd);

    return 0;
}
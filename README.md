# disassociatedWiFi

DisassociatedWiFi creates a virtual network interface (using the Linux TUN/TAP device driver) which sends and receives ethernet frames over an 802.11 (WiFi) interface, that has been placed in **monitor mode**, and supports **packet injection**.

Unlike regular WiFi, this system allows for truly uni-directional communication, as there are no acknowledgements at the data-link layer. The WiFi card still obeys standard CSMA/CA, however, care should be taken to select a channel that is relatively free to maximise the available bandwidth.

## Features
* No association - Packets are sent into the air, which able to be received by any number of receivers.
* Uni-directional communication - No acknowledgements or retransmissions at the link-layer.
* Regular interface - Treat it like any other ethernet interface

## Installation
Currently, there is no installation process, the application can simply be run inside of a screen instance.


### Send Path
1. An Ethernet frame is received at the virtual network interface, which has come from an other kernel or user space application.
2. The Ethernet frame is encapsulated (with some optimisations) inside an 802.11 frame.
3. The 802.11 frame is sent over-the-air, through a physical WiFi interface in monitor mode.

### Receive Path
1. An 802.11 frame is received from a physical WiFi interface in monitor mode.
2. If the destination address of the frame is valid, an ethernet frame is decapsulated.
3. The decapsulated ethernet frame is passed to the virtual network interface.

### Valid Receive Addresses
Currently, the only frames that will be received are those with a destination MAC address of ff:ff:ff:ff:ff:ff (broadcast address), or the MAC address of the __virtual__ interface (not that of the __physical__ interface).

Consequently, IPv4 and IPv6 multicast addresses are not supported, but should be easy to add.
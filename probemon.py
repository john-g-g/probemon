#!/usr/bin/env python3

import datetime
import argparse
import netaddr
import sys
import time
import os
import logging
import random
from scapy.all import *
from functools import partial

import signal
from multiprocessing import Process

logging.basicConfig(format='%(asctime)s\t%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

def unused_channel(channels):
    channel = random.randrange(1,12)
    while channel in channels:
        channel = random.randrange(1,12)
    return channel

def channel_hopper(interfaces, interval):
    while True:
        try:
            channels = []
            for interface in interfaces:
                channel = unused_channel(channels)
                channels.append(channel)
                logger.info('hopping to channel %s on %s',channel, interface)
                os.system(f'iwconfig {interface} channel {channel}')
            time.sleep(interval)
        except KeyboardInterrupt:
            break

def signal_handler(procs, signal, frame):
    for proc in procs:
        logger.info('terminating %s', proc)
        proc.terminate()
        proc.join()
    sys.exit(0)


def packet_callback(packet):
    if not packet.haslayer(Dot11):
        return

    # we are looking for management frames with a probe subtype
    # if neither match we are done here
    if packet.type != 0 or packet.subtype != 0x04:
        return

    # list of output fields
    fields = []

    # append the mac address itself
    fields.append(packet.addr2)

    # parse mac address and look up the organization from the vendor octets
    
    try:
        parsed_mac = netaddr.EUI(packet.addr2)
        fields.append(parsed_mac.oui.registration().org)
    except netaddr.core.NotRegisteredError as e:
        fields.append('UNKNOWN')

    # include the SSID in the probe frame
    fields.append(packet.info)
    
    # signal strength in dbm
    try:
        fields.append(packet.dBm_AntSignal)
    except Exception as e:
        logger.error(e)
    
    try:
        fields.append(packet.Channel)
    except Exception as e:
        logger.error(e)

    logger.info('\t'.join(map(str,fields)))

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-i', '--interface', nargs='+', help="capture interface")
    parser.add_argument('-o', '--output', default='probemon.log', help="logging output location")
    parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
    parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
    args = parser.parse_args()

    if not args.interface:
        print("error: at least one capture interface required, try --help")
        sys.exit(-1)

    # Start the channel hopper

    hopper_func = partial(channel_hopper, args.interface, 2)

    hopper_process = Process(target = hopper_func)
    hopper_process.start()

    procs = [hopper_process]
    interfaces = args.interface
    for interface in interfaces:
        sniff_func = partial(sniff,iface=args.interface, prn=packet_callback, store=0)
        sniff_proc = Process(target=sniff_func)
        sniff_proc.start()
        procs.append(sniff_proc)
    
    # Capture CTRL-C
    signal_handler_func = partial(signal_handler, procs)
    signal.signal(signal.SIGINT, signal_handler_func)


if __name__ == '__main__':
    main()

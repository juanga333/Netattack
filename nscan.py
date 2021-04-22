#!/bin/python3
import argparse
import signal
import subprocess
from scapy.all import os, random, sniff
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11ProbeReq


class Scan:
    __bssid: list
    __interface: str
    __clientprobes: list

    def __init__(self, interface):
        self.__bssid = []
        self.__clientprobes = []
        self.__interface = interface

    @staticmethod
    def print_row(len, bbsid, pwr, channel, encrypt, ssid):
        print("%-3s %-25s %-5s %-5s %-25s %-15s" % (len, bbsid, pwr, channel, encrypt, ssid))

    @staticmethod
    def print_row_client(len, macclient, ssid, pwr):
        print("%-3s %-25s %-25s %-5s" % (len, macclient, ssid, pwr))

    def channelHopping(self):
        r = random.randrange(1, 14)
        if r == 14:
            print(r)
        os.system('iw dev %s set channel %d' % (self.__interface, r))

    def getAllWifiDevices(self, packet):
        if packet.haslayer(Dot11):
            if packet.addr2 and packet.addr2 not in self.__bssid:
                try:
                    stats = packet[Dot11Beacon].network_stats()
                    crypto = stats.get("crypto")
                    self.print_row(len(self.__bssid), packet.addr2, packet.dBm_AntSignal, stats.get("channel"), crypto,
                                   packet.info.decode("utf-8"))
                    self.__bssid.append(packet.addr2)
                except:
                    pass

    def getClientsProbes(self, packet):
        if packet.haslayer(Dot11ProbeReq):
            if len(packet.info):
                testcase = str(packet.addr2), str(packet.info)
                if testcase not in self.__clientprobes:
                    self.__clientprobes.append(testcase)
                    self.print_row_client(len(self.__clientprobes), str(packet.addr2),
                                          str(packet.info.decode("utf-8")), packet.dBm_AntSignal)


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script deauthenticates a device from a router. It can be used to with all devices (ff:ff:ff:ff:ff:ff).\n"
                    "Prerequisites: You and your victim need to have wifi. ")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-a", "--getAllBssid", required=False, action='store_true',
                        help="This options get all mac of the nearby routers")
    parser.add_argument("-p", "--getClientProbes", required=False, action='store_true',
                        help="This options get client probes")

    args = parser.parse_args()

    scan = Scan(args.interface)
    if args.getAllBssid:
        if args.getMacBssid:
            print("You need to specify only one option: -g or -a")
        else:
            print("Press enter to kill the program")
            scan.print_row('', 'BSSID', 'PWR', 'CH', "CRYPT", "SSID")
            newpid = os.fork()
            if newpid == 0:
                sniff(iface=args.interface, prn=scan.getAllWifiDevices)
            else:
                newpid2 = os.fork()
                if newpid2 == 0:
                    while True:
                        scan.channelHopping()
                else:
                    input('')
                    os.kill(newpid, signal.SIGKILL)
                    os.kill(newpid2, signal.SIGKILL)
    elif args.getClientProbes:
        scan.print_row_client("", "MAC CLIENT", "SSID", "PWR")
        sniff(prn=scan.getClientsProbes)
    else:
        print("You need to specify one option (-a or -p)")

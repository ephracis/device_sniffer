Device Sniffer
==============

A network sniffer that counts and lists the number of devices that are present on the network.

Features:
* Total number of present devices
* MAC address of the device
* Packets sent to and from each device
* When the device was first seen
* When the device was last seen

## Requirements

You need to install a python module before you can run device_sniffer:

* **pylibpcap**<br/>
 The libpcap library for Python.<br/>
 http://sourceforge.net/projects/pylibpcap/


## Usage

You can run device_sniffer without any arguments, it will then automatically choose the interface to sniff on:<br/>
`$ python device_sniffer.py`

You can also tell it to sniff on a specific interface:<br/>
`$ python device_sniffer.py en0`

## Support

Need help? You can email me at my gmail where my username is: ephracis

## Contribute

You are free to contribute to the project. Extend it, refactor it, fix bugs you find, etc.

You can support my work by sending a contribution to the following bitcoin address:
14xHJbs8hCxXzxe9Facv162AZmWyYEeWb1

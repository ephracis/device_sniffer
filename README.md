Device Sniffer
==============

A network sniffer that counts and lists the number of devices present within range.

Features:
* Total number of present devices
* MAC address of the device
* Packets sent to and from each device
* When the device was first seen
* When the device was last seen

## Requirements

You need to install some packages before you can run Hermes:

* **pylibpcap**<br/>
 The libpcap library for Python.<br/>
 http://sourceforge.net/projects/pylibpcap/


## Usage

You can either run device_sniffer without any arguments:<br/>
`$ python device_sniffer.py`

It will then automatically choose an interface to sniff on. You can also specify the interface if you want:<br/>
`$ python device_sniffer.py en0`

## Support

You can email me at my gmail where my username is: ephracis

## Contribute

You are free to contribute to the project. Extend it, refactor it, fix bugs you find, etc.

You can support my work by sending a contribution to the following bitcoin address:
14xHJbs8hCxXzxe9Facv162AZmWyYEeWb1

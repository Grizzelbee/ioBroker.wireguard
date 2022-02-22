![Logo](admin/Logo_of_WireGuard.svg)

# ioBroker.wireguard
![Logo](admin/wireguard.svg)

[![NPM version](https://img.shields.io/npm/v/iobroker.wireguard.svg)](https://www.npmjs.com/package/iobroker.wireguard)
[![Downloads](https://img.shields.io/npm/dm/iobroker.wireguard.svg)](https://www.npmjs.com/package/iobroker.wireguard)
![Number of Installations](https://iobroker.live/badges/wireguard-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/wireguard-stable.svg)
![Test and Release](https://github.com/grizzelbee/ioBroker.wireguard/workflows/Test%20and%20Release/badge.svg)
![CodeQL](https://github.com/Grizzelbee/ioBroker.wireguard/actions/workflows/codeQL.yml/badge.svg)
[![NPM](https://nodei.co/npm/iobroker.wireguard.png?downloads=true)](https://nodei.co/npm/iobroker.wireguard/)

## wireguard adapter for ioBroker
Connect to WireGuard hosts and grab connection information on peers. This adapter is intended to be a monitoring instance for your WireGuard hosts. 

## Prerequisites
* running ssh server on every host to monitor
* username and password of a user with the permission to execute the wg command 

## Installation steps
* Check whether your WireGuard host is running an ssh server. If not - install one.
* make sure the user you like to use for this is able to execute `wg` (same for Windows and Linux). **This user needs admin privileges!**
* Do this for every host you like to monitor
* Install the adapter and configure it

## Config options
Since WireGuard internally only uses the public keys to identify peers, but this is pretty inconvenient to read and recognize for humans the translation page was added. Feel free to add public keys and Names to it to get the names integrates in the object tree.

* Main page
  - Name: Just a symbolic name for the host, since it's more convenient than it's IP address
  - Host address: IP address of the host. A fqdn may work also but is not tested
  - User: The user which executes the script on the host
  - Password: Password for this
* Translation page
    - Public Key: The public key of one of your peers
    - group name: A symbolic name for this peer
 

## How it works
* info.connection of the adapter is used to indicate that at least one WireGuard interface is online and reported by `wg show all`. If no Wireguard interface is online - nothing is reported. In that case an error gets logged and the adapters traffic light turns yellow. 
* This adapter opens an ssh shell on every configured host, executes the `wg show all dump` command, drops the shell and parses the result.
* Since every public key is unique, the adapter uses them to translate the public key into user-friendly readable and recognisable names.
* WireGuard unfortunately doesn't provide the "connected" state by itself. It only provides the last handshake information.
This adapter calculates the connected state that way, that it assumes a peer is connected when the last handshake is received
less than 130 seconds before. This is because handshakes usually occur every 120 seconds.

## DANGER! Keep your eyes and your mind open! 
Since the `wg` command (which is executed to grab the state of WireGuard) requires permissions near to `root` (admin privileges), think well of what you are doing here and how you configure the user you place in config.
To protect these credentials as well as possible both - username and password - are encrypted. 

## known issues
* none

## Changelog

### v0.9.5 (2022-02-22)
* (grizzelbee) New: dropped use of wg-json script - not needed anymore
* (grizzelbee) New: making internal use of wg show all dump command and self parsing the result
* (grizzelbee) New: Added windows support by using the wg show all command

### v0.9.2 (2022-02-20)
* (grizzelbee) Fix: removed unnecessary secret from index_m.html file
* (grizzelbee) Fix: Using info.connection of adapter to indicate that at least one interface is online.
* (grizzelbee) Fix: Updated adapter icon

### v0.9.1 (2022-02-19)
* (grizzelbee) New: Improved optical quality of admin page - no technical improvements

### v0.9.0 (2022-02-18)
* (grizzelbee) New: Improved documentation
* (grizzelbee) New: Username and password for WireGuard hosts are getting encrypted now

### v0.8.0 (2022-02-17)
* (grizzelbee) New: admin extended with second page
* (grizzelbee) New: data file is getting parsed
* (grizzelbee) New: data tree is getting populated
* (grizzelbee) New: entire basic functionality is implemented
* (grizzelbee) New: added plugin sentry

### v0.2.0 (2022-02-16)
* (grizzelbee) New: admin is working as expected
* (grizzelbee) New: first steps in backend

### v0.1.0 (2022-02-14)
* (grizzelbee) working on admin

### v0.0.1
* (grizzelbee) initial release


## sentry.io
This adapter uses sentry.io to collect details on crashes and report it automated to the author.
The [ioBroker.sentry plugin](https://github.com/ioBroker/plugin-sentry) is used for it. Please refer to
the [plugin homepage](https://github.com/ioBroker/plugin-sentry) for detailed information on what the plugin does, which information is collected and how to disable it, if you don't like to support the author with you're information on crashes.

### Disclaimer
This project is not related to WireGuard in any way. The name WireGuard and the WireGuard logo are only used to refer to this project and are the property of their owners. They are not part of this project.


## License
MIT License


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Copyright
Copyright (c) 2022 grizzelbee <open.source@hingsen.de>

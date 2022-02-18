![Logo](admin/Logo_of_WireGuard.svg)

# ioBroker.wireguard
![Logo](admin/wireguard.svg)

[![NPM version](https://img.shields.io/npm/v/iobroker.wireguard.svg)](https://www.npmjs.com/package/iobroker.wireguard)
[![Downloads](https://img.shields.io/npm/dm/iobroker.wireguard.svg)](https://www.npmjs.com/package/iobroker.wireguard)
![Number of Installations](https://iobroker.live/badges/wireguard-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/wireguard-stable.svg)
![Test and Release](https://github.com/grizzelbee/ioBroker.wireguard/workflows/Test%20and%20Release/badge.svg)
[![NPM](https://nodei.co/npm/iobroker.wireguard.png?downloads=true)](https://nodei.co/npm/iobroker.wireguard/)

## wireguard adapter for ioBroker
Connect to WireGuard hosts and grab connection information on peers. This adapter is intended to be a monitoring instance for your WireGuard hosts. 

## Prerequisites
* running ssh server on every host to monitor
* username and password of a user with the permission to execute the wg command 
* wg-json script is installed and executable

## Installation steps
* Check whether your WireGuard host is running an ssh server. If not - install one.
* Install the wg-json script provided by this project in the folder `wg-tools/linux` and get it running. Usually it should be sufficient to copy it to `/usr/bin/wg-json` (yes - remove the .sh) and give it 755 permissions by executing `chown 755 wg-json`. You can test it by calling `wg-json` from your home directory. If you get a json structure printed to stdout, it works.
* Since `wg-json` calls `wg show all all dump` internally the user executing it needs the same permissions as `wg` itself. `sudo` is not supported, since it needs a second password entering. 
* make sure the user you like to use for this is able to execute `wg-json`
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
* This adapter opens an ssh shell on every configured host, executes the wg-json script, drops the shell and parses the result.
* Since every public key is unique, the adapter uses them to translate the public key into user-friendly readable and recognisable names.
* WireGuard unfortunately doesn't provide the "connected" state by itself. It only provides the last handshake information.
This adapter calculated the connected state that way, that it assumes a peer is connected when the last handshake is received
less than 130 seconds before. This is because handshakes usually occur every 120 seconds.

## DANGER!
Since the `wg` command (which is executed to grab the state of WireGuard) requires permissions near to `root`, think well of what you are doing here and how you configure the user you place in config.
To protect these credentials as well as possible both - username and password - are encrypted. 

## sentry.io
This adapter uses sentry.io to collect details on crashes and report it automated to the author. The ioBroker.sentry plugin is used for it. Please refer to the plugin homepage for detailed information on what the plugin does, which information is collected and how to disable it, if you don't like to support the author with your information on crashes.

## known issues
* This project currently only supports WireGuard on Linux. Windows support is planned for the future. Volunteers for this feature are welcome.
* Username and Passwords of hosts are currently not encrypted

## Changelog

### todo
* Do translation
* activate git-Actions
* activate git-code quality test

### 0.9.0 (2022-02-18)
* (grizzelbee) New: Improved documentation
* (grizzelbee) New: Username and password for WireGuard hosts are getting encrypted now

### 0.8.0 (2022-02-17)
* (grizzelbee) New: admin extended with second page
* (grizzelbee) New: data file is getting parsed
* (grizzelbee) New: data tree is getting populated
* (grizzelbee) New: entire basic functionality is implemented
* (grizzelbee) New: added plugin sentry

### 0.2.0 (2022-02-16)
* (grizzelbee) New: admin is working as expected
* (grizzelbee) New: first steps in backend

### 0.1.0 (2022-02-14)
* (grizzelbee) working on admin

### 0.0.1
* (grizzelbee) initial release


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

# WGVPN

A proof-of-concept MacOS client for a simple managed WireGuard VPN service

## Introduction

A server implementation provides a simple API for clients to discover
VPN configuration data. Each client uses a TLS client certificate to
access the API and, based on the CommonName presented, the server can
select and activate respective IP address/public key bindings on the
WireGuard server.

An endpoint can be used to send the end user to an OIDC authentication
flow (possibly using 2FA) which, when passed, will add the device's IP
address to firewall rules. Tokens tracked by the server may be
periodically refreshed to keep the client active - failure to receive
a refreshed token, or client certificate invalidation via OSCP can
block access to the client.

Server implementation is not currently openly available, but you can
build your own. Or raise an issue if interested.

## Usage

Needs the wireguard-tools/wireguard-go packages from Homebrew.

Two processes need to be run.

* A WireGuard management process - `sudo make wg` - this needs sudo access to create utun devices
* A menu bar based client process - `make vpn` - see the [Makefile](Makefile) for overrides to make this work with your infrastructure 

The client process will search the keychain for a matching client
certificate (can be overridden with a PEM file on the command line)
and create a keychain password entry with a generated private key and
server public key if it does not exist. It will then poll the server
for status information.

## API endpoints

### /api/1/status

Returns key:value pairs indicating the status of the user's
connection. Can be used to indicate that the user may need to
authenticate via, eg., an OIDC flow.

```
{"active":true}
```

### /api/1/beacon

Returns a 200 status code when the VPN is fully working. Could be
implemented as a redirect to an internal service, or another port on
the VPN server bound to a port on an internal address.

### /api/1/config

Accepts a POST of the client's public key - optionally may add
temporary access if the client does not yet have a registered
key. Returns the settings that the client should use to access the
VPN. Server's public key is stored on first use along with generated
private key and subsequently is compared with the returned value to
detect spoofing - in which case the tunnel is not brought up and the
stored keychain entry should be deleted in case of a genuine need to
re-key.

Server returns the client's public key such the the client can detect
that server has an incorrect key stored and alert the user to the need
to contact support to re-key the device.

POST:

```
{"PublicKey": "+Njc296qpzKNXtkMcdbvCYAObhhg1C0o/dU2b1fu6GI="}
```

Returns:

```
{
 "Interface": {
  "PublicKey": "+Njc296qpzKNXtkMcdbvCYAObhhg1C0o/dU2b1fu6GI=",
  "Address": "10.1.2.3",
  "MTU": 1400,
  "DNS": [
   "8.8.8.8",
   "1.1.1.1"
  ]
 },
 "Peer": {
  "PublicKey": "nEQMporDAX28HB0rTMrozOPnYSdYnbkYhmS7uG5CdQg=",
  "AllowedIPs": [
   "10.0.0.0/8",
   "172.16.0.0/12"
  ],
  "Endpoint": "vpn.example.com:51820"
 }
}
```


## Native MacOS client

This is a PoC. The intention would be to build a first-class MacOS
implementation in Swift with appropriate entitlements. Alas, I am not
an Apple developer.

A native client would need/implement:

* WireGuardKit / NEPacketTunnelProvider integration - Network Extensions Entitlement
* Keychain access for certificate/private key
* Access the simple API via HTTP with client cert
* Ability to launch browser window for AD auth, etc.
* A Simple UI - status menu item, dropdown options
* Generate private key on first use and save along with server public key
* Check server key against stored entry when connecting - alert user of mismatch
* Post pubkey when connecting to generate notification server side in case of mismatch

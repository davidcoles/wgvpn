/*
 * wgvpn client - Copyright (C) 2023-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davidcoles/certstore"

	"github.com/caseymrm/menuet"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/curve25519"
)

const DIRECTORY = "/var/run/wireguard/"
const SOCKET = DIRECTORY + "wgvpn"
const BASEURL = "http://localhost/"

var ROOTCA = "MyCA"
var NAME = "MyVPN"
var DOMAIN = "vpn.example.com"
var SERVICE = DOMAIN
var PORTAL = "https://" + DOMAIN + "/"
var ACTIVE = "activate"
var CONFIG = "api/1/config"
var BEACON = "api/1/beacon"
var STATUS = "api/1/status"

var CLIENT *http.Client

type Private [32]byte

const (
	I_INITIALISING = "💤"
	I_CONNECTING   = "🔄"
	I_ESTABLISHED  = "✅"
	I_DOWN         = "⛔️"
	I_WARNING      = "⚠️"
	I_BLOCKED      = "🚫"
	I_BROKEN       = "❌"
	I_UNREACHABLE  = "🆘"
	I_WTF          = "⁉️"
)

type WireGuard struct {
	Interface Interface
	Peer      Peer
}

type Interface struct {
	//PrivateKey string
	PrivateKey Private
	PublicKey  string
	Address    string
	MTU        uint16
	DNS        []string
}

type Peer struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
}

var wg = flag.Bool("w", false, "manage wireguard device")
var cm = flag.Bool("c", false, "client mode")

func main() {

	flag.Parse()
	args := flag.Args()

	if *wg {
		wgtool()
		return
	}

	CLIENT = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", SOCKET)
			},
		},
	}

	go start(*cm, args)

	menuet.App().Name = NAME
	menuet.App().Label = "VPN"
	menuet.App().RunApplication()
}

func start(cm bool, args []string) {

	var client *http.Client
	var account string
	var err error

	if len(args) > 0 {
		client, account, err = cert(args[0])
	} else {
		client, account, err = getclient(ROOTCA)
	}

	if err != nil || client == nil {
		alert := menuet.Alert{Buttons: []string{"OK"}}
		alert.MessageText = "No client certificate found"
		alert.InformativeText = "Ensure that a certificate from the " + ROOTCA + " certificate authority is in your keystore"
		menuet.App().Alert(alert)
		log.Fatal(err)
	}

	if cm {
		getkey(client, account)
	} else {
		frontend(client, "", Private{}, false)
	}
}

func getkey(client *http.Client, account string) {

	keypeer, err := retrievekey(SERVICE, account)

	if err != nil {
		k, err := genkey()

		if err != nil {
			alert := menuet.Alert{Buttons: []string{"OK"}}
			alert.MessageText = "Unable to generate encryption key"
			alert.InformativeText = fmt.Sprint("Error:", err)
			menuet.App().Alert(alert)
			log.Fatal(err)
		}

		key := encode(k)
		pub := encode(pubkey(k))

		wg := getconfig(client, PORTAL+CONFIG, pub)

		if wg == nil {
			alert := menuet.Alert{Buttons: []string{"OK"}}
			alert.MessageText = "Connection failed"
			alert.InformativeText = "Couldn't retrieve config from server"
			menuet.App().Alert(alert)
			log.Fatal("Connection failed")
		}

		peer := wg.Peer.PublicKey

		_, ok := decode(peer)

		if !ok {
			alert := menuet.Alert{Buttons: []string{"OK"}}
			alert.MessageText = "Connection failed"
			alert.InformativeText = "Couldn't retrieve public key from server"
			menuet.App().Alert(alert)
			log.Fatal("wg.Peer.PublicKey")
		}

		keypeer = key + ":" + peer

		err = storekey(SERVICE, account, keypeer)

		if err != nil {
			alert := menuet.Alert{Buttons: []string{"OK"}}
			alert.MessageText = "Unable to store encryption key"
			alert.InformativeText = fmt.Sprint("Error:", err)
			menuet.App().Alert(alert)
			log.Fatal(err)
		}

		alert := menuet.Alert{Buttons: []string{"OK"}}
		alert.MessageText = "New key generated"
		alert.InformativeText = "A new " + SERVICE + " key for device " + account + " was generated and stored in your keychain"
		menuet.App().Alert(alert)

		getconfig(client, PORTAL+CONFIG, pub)
	}

	kp := strings.Split(keypeer, ":")

	if len(kp) != 2 {
		menuet.App().Alert(menuet.Alert{
			Buttons:         []string{"OK"},
			MessageText:     "Mangled keys",
			InformativeText: "Mangled keys",
		})
		log.Fatal(keypeer)
	}

	priv := kp[0]
	peer := kp[1]

	key, ok := decode(priv)

	if !ok {
		alert := menuet.Alert{Buttons: []string{"OK"}}
		alert.MessageText = "Corrupt encryption key"
		alert.InformativeText = "Delete the keychain " + SERVICE + " entry for " + account + " and try again"
		log.Fatal(err)
	}

	_, ok = decode(peer)

	if !ok {
		alert := menuet.Alert{Buttons: []string{"OK"}}
		alert.MessageText = "Corrupt encryption key"
		alert.InformativeText = "Server's key is corrupt"
		log.Fatal(err)
	}

	pub := encode(pubkey(key))

	fmt.Println("PUBKEY", pub)

	frontend(client, peer, key, true)
}

func tsf(x uint64) string {
	n := float64(x)

	suffix := []string{"", "K", "M", "G", "T", "P", "E", "Z", "Y"}

	if n < 1000 {
		return fmt.Sprint(n)
	}

	for n > 1000 && len(suffix) > 1 {
		n /= 1000
		suffix = suffix[1:]
	}

	if n > 100 {
		return fmt.Sprintf("%.0f%s", n, suffix[0])
	}

	if n > 10 {
		return fmt.Sprintf("%.1f%s", n, suffix[0])
	}

	return fmt.Sprintf("%.2f%s", n, suffix[0])
}

func frontend(client *http.Client, peer string, key Private, full bool) {
	var up bool
	pub := encode(pubkey(key))

	var rx, tx uint64
	var rxps, txps uint64

	update := make(chan bool)

	icon := I_INITIALISING
	text := "Initialising"
	link := PORTAL

	menuet.App().SetMenuState(&menuet.MenuState{
		Title: NAME + icon,
	})

	menuitems := func() []menuet.MenuItem {
		var items []menuet.MenuItem

		items = append(items, menuet.MenuItem{
			Type: "Status",
			Text: text + " (open portal)",
			Clicked: func() {
				exec.Command("/usr/bin/open", link).Output()
			},
		})

		if full {

			//items = append(items, menuet.MenuItem{Type: menuet.Separator})

			label := DOMAIN

			if up {
				label = fmt.Sprintf(DOMAIN+" Tx %sB/s, Rx %sB/s", tsf(txps), tsf(rxps))
			}

			items = append(items, menuet.MenuItem{
				Type: "Status",
				//Text:  "Enable",
				Text:  label,
				State: up,
				Clicked: func() {

					if up {
						disconnect()
						update <- true
						update <- true
					} else {

						wg := getconfig(client, PORTAL+CONFIG, pub)

						if wg == nil {
							alert := menuet.Alert{Buttons: []string{"OK"}}
							alert.MessageText = "Connection failed"
							alert.InformativeText = "Couldn't retrieve config from server"
							menuet.App().Alert(alert)
							return
						}

						if wg.Peer.PublicKey != peer {
							alert := menuet.Alert{Buttons: []string{"OK"}}
							alert.MessageText = "Server key has changed"
							alert.InformativeText = "The key that the server uses has changed.\nPlease contact support."
							menuet.App().Alert(alert)
							return
						}

						if wg.Interface.PublicKey != pub {
							alert := menuet.Alert{Buttons: []string{"OK"}}
							alert.MessageText = "Mismatched Key"
							alert.InformativeText = "Please let support know that your key has changed to: " + pub
							menuet.App().Alert(alert)
							return
						}

						wg.Interface.PrivateKey = key

						icon = I_CONNECTING
						menuet.App().SetMenuState(&menuet.MenuState{Title: NAME + icon})

						err := connect(*wg)

						update <- true
						update <- true

						if err != nil {
							alert := menuet.Alert{Buttons: []string{"OK"}}
							alert.MessageText = "Couldn't start WireGuard session"
							alert.InformativeText = fmt.Sprint("Error: ", err)
							menuet.App().Alert(alert)
							return
						}
					}
				},
			})

			//items = append(items, menuet.MenuItem{Type: menuet.Separator})

			items = append(items, menuet.MenuItem{
				Type: "Keys",
				Text: "Show keys",
				Clicked: func() {
					alert := menuet.Alert{Buttons: []string{"OK", "Private key"}}
					alert.MessageText = "Public Keys"
					alert.InformativeText = "Public key: " + pub + "\nServer key: " + peer
					ret := menuet.App().Alert(alert)

					if ret.Button == 1 {
						alert := menuet.Alert{Buttons: []string{"OK"}}
						alert.MessageText = "Private key"
						alert.InformativeText = encode(key)
						menuet.App().Alert(alert)
					}

					return
				},
			})

		}
		return items
	}

	menuet.App().Children = menuitems

	ticker := time.NewTicker(5 * time.Second)

	defer ticker.Stop()

	var ts int64

	for {

		rxt, txt := stats()
		tst := time.Now().Unix()

		if ts > 0 {
			d := tst - ts

			if d > 0 {
				txps = (txt - tx) / uint64(d)
				rxps = (rxt - rx) / uint64(d)
			}
		}
		ts = tst
		rx = rxt
		tx = txt

		menuet.App().MenuChanged()

		l := link
		i := icon
		t := text
		u := up

		var x uint8

		if pub != "" {
			u = (state() == nil)
		}

		_, err := get200(client, PORTAL+BEACON)
		//b, _ := get(client, PORTAL+BEACON, "beacon")
		//fmt.Println("BEACON:", err)
		if err == nil {
			x |= 0x2
		}

		a, e := get(client, PORTAL+STATUS, "authenticated")
		//fmt.Println("ACTIVE:", e)
		if a {
			x |= 0x1
		}

		//log.Println("beacon", b)

		t = "Disabled"
		l = PORTAL
		i = I_DOWN

		if u || !full {
			switch x {
			case 3:
				i = I_ESTABLISHED
				t = "Established"
			case 2: // wg up but not auth
				i = I_WARNING
				t = "Authentication required"
				l = PORTAL + ACTIVE
			case 1: // auth but no wg
				i = I_BLOCKED
				t = "Traffic blocked"
			default:
				i = I_BROKEN
				t = "Broken"
			}
		}

		if e != nil {
			i = I_UNREACHABLE
			t = "Unreachable"
		}

		menuet.App().SetMenuState(&menuet.MenuState{
			Title: NAME + icon,
		})

		menuet.App().MenuChanged()

		if l != link || i != icon || t != text || u != up {
			link = l
			icon = i
			text = t
			up = u
			menuet.App().MenuChanged()
		}

		select {
		case <-ticker.C:
		case <-update:
		}
	}

}

func stats() (rx, tx uint64) {

	resp, err := CLIENT.Get(BASEURL + "stats")

	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return
	}

	lines := strings.Split(string(b), "\n")

	re := regexp.MustCompile(`^\S{44}\s+(\d+)\s+(\d+)`)

	for _, v := range lines {
		m := re.FindStringSubmatch(v)

		if len(m) == 3 {
			rx, _ = strconv.ParseUint(m[1], 10, 64)
			tx, _ = strconv.ParseUint(m[2], 10, 64)
			return rx, tx
		}

	}
	return
}

func state() error {

	resp, err := CLIENT.Get(BASEURL + "state")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return errors.New("StatusCode != 200")
	}

	return nil
}

func fetch(client *http.Client, url string) error {

	resp, err := client.Get(url)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return errors.New("StatusCode != 200")
	}

	return nil
}

func disconnect() error {

	resp, err := CLIENT.Get(BASEURL + "down")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return errors.New("StatusCode != 200")
	}

	return nil
}

func connect(wg WireGuard) error {

	js, err := json.MarshalIndent(&wg, "", "  ")

	if err != nil {
		return err
	}

	resp, err := CLIENT.Post(BASEURL+"up", "application/json", bytes.NewBuffer(js))

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return errors.New("StatusCode != 200")
	}

	//b, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	log.Println(err)
	//}

	return nil
}

func getclient(sn string) (*http.Client, string, error) {

	id, cn, err := identity(sn)

	if err != nil {
		//return nil, errors.New("Couldn't find my identity")
		return nil, cn, err
	}

	// Get a crypto.Signer for the identity.
	signer, err := id.Signer()
	if err != nil {
		return nil, cn, err
	}

	crt, err := id.Certificate()
	if err != nil {
		return nil, cn, err
	}

	tlsCrt := tls.Certificate{
		Certificate: [][]byte{crt.Raw},
		PrivateKey:  signer,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCrt},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}

	return client, cn, nil
}

func identity(cn string) (certstore.Identity, string, error) {

	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.
	store, err := certstore.Open()
	if err != nil {
		return nil, "", err
	}
	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()
	if err != nil {
		return nil, "", err
	}

	// Iterate through the identities, looking for the one we want.
	for _, ident := range idents {

		crt, err := ident.Certificate()

		if err == nil && crt.Issuer.CommonName == cn {
			return ident, crt.Subject.CommonName, nil
		}

		ident.Close()
	}

	return nil, "", errors.New("Couldn't find my identity")
}

func retrievekey(service, account string) (string, error) {
	// get password
	secret, err := keyring.Get(service, account)
	if err != nil {
		return "", err
	}
	return secret, nil
}

func storekey(service, account, password string) error {
	// set password
	return keyring.Set(service, account, password)
}

func genkey() ([32]byte, error) {
	var key [32]byte

	n, err := rand.Read(key[:])

	if err != nil {
		return key, err
	}

	if n != 32 {
		return key, errors.New("Failed to read 32 bytes fron random source")
	}

	// https://cr.yp.to/ecdh.html

	key[0] &= 248
	key[30] &= 127
	key[31] |= 64

	return key, nil
}

func pubkey(private [32]byte) [32]byte {

	var public [32]byte

	curve25519.ScalarBaseMult(&public, &private)

	var foo [32]byte

	x, err := curve25519.X25519(private[:], curve25519.Basepoint)

	if err != nil || len(x) != 32 {
		log.Fatal(err, len(x))
	}

	copy(foo[:], x[:])

	if foo != public {
		log.Fatal(foo, public)
	}

	return public
}

func encode(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func decode(s string) (key [32]byte, b bool) {
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		copy(key[:], k[:])
		b = true
	}
	return
}

func getconfig(client *http.Client, url string, pub string) *WireGuard {

	/*
		type message struct {
			PublicKey string
		}

		m := message{PublicKey: pub}
		j, err := json.Marshal(&m)

		fmt.Println(url, string(j))

		resp, err := client.Post(url, "application/json", bytes.NewReader(j))
	*/

	resp, err := client.Get(url)

	fmt.Println(err)

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	js, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var wg WireGuard

	err = json.Unmarshal(js, &wg)

	if err != nil {
		return nil
	}

	return &wg
}

func _getconfig(client *http.Client, url string, pub string) *WireGuard {

	type message struct {
		PublicKey string
	}

	m := message{PublicKey: pub}
	j, err := json.Marshal(&m)

	fmt.Println(url, string(j))

	resp, err := client.Post(url, "application/json", bytes.NewReader(j))

	fmt.Println(err)

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	js, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var wg WireGuard

	err = json.Unmarshal(js, &wg)

	if err != nil {
		return nil
	}

	return &wg
}

func cert(pem string) (*http.Client, string, error) {

	var account string

	// load cert
	cert, err := tls.LoadX509KeyPair(pem, pem)

	if err != nil {
		log.Fatal(err)
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//RootCAs:      caCertPool,
	}

	tlsConfig.BuildNameToCertificate()

	for k, _ := range tlsConfig.NameToCertificate {
		account = k
	}

	if account == "" {
		return nil, account, nil
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}

	return client, account, nil
}

func get(client *http.Client, url, param string) (bool, error) {
	resp, err := client.Get(url)

	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	js, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var cf map[string]interface{}

	err = json.Unmarshal(js, &cf)

	if err != nil {
		return false, nil
	}

	//log.Println("****", cf)

	if v, ok := cf[param]; ok {
		if b, ok := v.(bool); ok {
			return b, nil
		}
	}
	return false, nil
	//return cf[param], nil
}

func get200(client *http.Client, url string) ([]byte, error) {

	resp, err := client.Get(url)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Status code not 200")
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

/**********************************************************************/

func wgtool() {

	exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()
	exec.Command("/bin/sh", "-c", "cd "+DIRECTORY+" && rm utun?.sock wg?.name").Output()

	os.Remove(SOCKET)
	exec.Command("mkdir", DIRECTORY).Output()

	s, err := net.Listen("unix", SOCKET)
	if err != nil {
		log.Fatal(err)
	}

	exec.Command("chown", "root:staff", SOCKET).Output()
	exec.Command("chmod", "g+rw", SOCKET).Output()

	var utun string
	var mu1, mu2 sync.Mutex

	var quit chan bool

	http.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		mu2.Lock()
		if quit != nil {
			close(quit)
			quit = nil
		}
		mu2.Unlock()
	})

	http.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		mu2.Lock()
		defer mu2.Unlock()

		if quit == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {

		mu2.Lock()
		defer mu2.Unlock()

		if quit == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		out, err := exec.Command("wg", "show", utun, "transfer").Output()

		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	})

	http.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Hello, World!\n"))
			return
		}

		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var wg WireGuard

		err = json.Unmarshal(body, &wg)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		fmt.Println(wg)

		if !mu1.TryLock() {
			log.Println("mu1.TryLock")
			w.WriteHeader(http.StatusConflict)
			return
		}

		var done chan bool

		mu2.Lock()
		defer mu2.Unlock()

		utun, quit, done = session(wg)

		w.WriteHeader(http.StatusOK)

		go func() {
			defer func() {
				mu2.Lock()
				quit = nil
				mu2.Unlock()
				mu1.Unlock()
			}()

			if done == nil {
				return
			}
			<-done
			exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()
		}()

	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func session(wg WireGuard) (string, chan bool, chan bool) {

	quit := make(chan bool)

	utun, done := wireguard(quit)

	if utun == "" {
		return "", nil, nil
	}

	mtu := fmt.Sprint(wg.Interface.MTU)
	exec.Command("ifconfig", utun, "inet", wg.Interface.Address+"/32", wg.Interface.Address, "alias").Output()
	exec.Command("ifconfig", utun, "mtu", mtu).Output()
	exec.Command("ifconfig", utun, "up").Output()

	for _, route := range wg.Peer.AllowedIPs {
		//fmt.Println(route)
		exec.Command("route", "-q", "-n", "add", "-inet", route, "-interface", utun).Output()
	}

	conf := setconf(wg)

	cmd := exec.Command("wg", "setconf", utun, "/dev/stdin")

	stdin, err := cmd.StdinPipe()

	if err != nil {
		log.Fatal(err)
	}

	err = cmd.Start()

	if err != nil {
		log.Fatal(err)
	}

	stdin.Write([]byte(conf))

	stdin.Close()

	networksetup := []string{"-setdnsservers", "Wi-Fi"}
	networksetup = append(networksetup, wg.Interface.DNS[:]...)
	log.Println(networksetup)
	exec.Command("networksetup", networksetup[:]...).Output()

	err = cmd.Wait()

	//exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()

	if err != nil {
		log.Fatal(err)
	}

	return utun, quit, done
}

func setconf(wg WireGuard) string {
	conf := []string{"[Interface]"}
	conf = append(conf, "PrivateKey = "+encode(wg.Interface.PrivateKey))
	conf = append(conf, "[Peer]")
	conf = append(conf, "PublicKey = "+wg.Peer.PublicKey)
	conf = append(conf, "Endpoint = "+wg.Peer.Endpoint)
	conf = append(conf, "AllowedIPs = "+strings.Join(wg.Peer.AllowedIPs, ","))
	conf = append(conf, "")
	return strings.Join(conf, "\n")
}

func wireguard(quit chan bool) (string, chan bool) {

	name := DIRECTORY + "/wgvpn.name"
	done := make(chan bool)

	go func() {
		cmd := "WG_TUN_NAME_FILE=" + name + " /opt/homebrew/bin/wireguard-go -f utun"
		exec.Command("/bin/sh", "-c", cmd).Output()
		os.Remove(name)
		close(done)
	}()

again:
	timer := time.NewTimer(1 * time.Second)

	select {
	case <-done:
		return "", done
	case <-timer.C:
	}

	f, err := os.Open(name)

	if err != nil {
		fmt.Println(err)
		goto again
	}

	bytes, err := ioutil.ReadAll(f)

	utun := string(bytes[0 : len(bytes)-1])

	sock := DIRECTORY + "/" + utun + ".sock"

	go func() {
		select {
		case <-done:
		case <-quit:
			os.Remove(sock)
		}
	}()

	return utun, done
}

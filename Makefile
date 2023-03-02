
all: wgvpn

clean:
	rm -f wgvpn

# Override these on the command line to build for your environment
# make wgvpn ROOTCA=Snakeoil NAME=CorpVPN DOMAIN=vpn.mydomain.com

NAME 	?= MyVPN
ROOTCA 	?= MyCA
DOMAIN 	?= vpn.example.com
SERVICE ?= $(DOMAIN)

FLAGS = -X main.NAME=$(NAME) \
	-X main.ROOTCA=$(ROOTCA) \
	-X main.DOMAIN=$(DOMAIN) \
	-X main.SERVICE=$(SERVICE)

wgvpn: wgvpn.go
	go build -ldflags "$(FLAGS)" -o $@ wgvpn.go

 # Define PEM=<my-client-cert-file.pem> on the command line to avoid keychain access requests
vpn:
	go run -ldflags "$(FLAGS)" wgvpn.go -c $(PEM)

wg:
	go run wgvpn.go -w

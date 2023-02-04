
all: wgvpn

clean:
	rm -f wgvpn

# Override these on the command line to build for your environment
# make wgvpn ROOTCA=Snakeoil NAME=CorpVPN DOMAIN=vpn.mydomain.com

NAME 	?= MyVPN
SERVICE ?= $(NAME)
ROOTCA 	?= MyCA
DOMAIN 	?= vpn.example.com

FLAGS = -X main.NAME=$(NAME) \
	-X main.SERVICE=$(SERVICE) \
	-X main.DOMAIN=$(DOMAIN) \
	-X main.ROOTCA=$(ROOTCA)

wgvpn: wgvpn.go
	go build -ldflags "$(FLAGS)" -o $@ wgvpn.go

 # Define PEM=<my-client-cert-file.pem> on the command line to avoid keychain access requests
vpn:
	go run -ldflags "$(FLAGS)" wgvpn.go -c $(PEM)

wg:
	go run wgvpn.go -w

# SOCKS5-proxy
SOCKS is used to delegate the traffic flow between client and server and acts as a proxy.
The package implement the revision 5 specification:
* [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)

#### Features:
- [ ] Support TCP
- [ ] Support UDP
- [ ] Username/Password authentication
- [ ] TLS encryption
- [ ] Request Multiplexing
  - [ ] Connection reusability: connection 1:1 queue with n clients

#### Examples:
```go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Wa4h1h/SOCKS5-proxy/credentials"
	"github.com/Wa4h1h/SOCKS5-proxy/proxy"
)

func main() {
	// using in memory credentials
	creds := credentials.NewInMemoryCreds()
	creds.Seed(map[string]string{
		"test": "test",
	})

	s := proxy.NewServer(proxy.WithCredentials(creds))

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	defer func() {
		s.Close()
		log.Printf("stop listening on :%s\n", s.Listener.Addr().String())
	}()

	// listen for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

```
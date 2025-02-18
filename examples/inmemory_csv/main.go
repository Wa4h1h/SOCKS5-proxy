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
	creds := credentials.NewInMemoryCreds()
	if err := creds.SeedFromCSV("creds.csv"); err != nil {
		panic(err)
	}

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

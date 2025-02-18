package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Wa4h1h/SOCKS5-proxy/auth"
	"github.com/Wa4h1h/SOCKS5-proxy/credentials"
	"github.com/Wa4h1h/SOCKS5-proxy/utils"
)

func NewServer(opts ...ServerConfigOpt) *Server {
	s := &Server{
		Config: &DefaultServerConfig,
	}

	for _, o := range opts {
		o(s.Config)
	}

	return s
}

func WithDelay(delay int) ServerConfigOpt {
	return func(config *ServerConfig) {
		config.Delay = delay
	}
}

func WithDelayInc(delayInc int) ServerConfigOpt {
	return func(config *ServerConfig) {
		config.DelayInc = delayInc
	}
}

func WithBackoffLimit(backoffLimit int) ServerConfigOpt {
	return func(config *ServerConfig) {
		config.BackoffLimit = backoffLimit
	}
}

func WithCredentials(creds credentials.CredentialsVerifier) ServerConfigOpt {
	return func(config *ServerConfig) {
		config.Credentials = creds
	}
}

func (s *Server) ListenAndServe() error {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: utils.ListenPort,
	})
	if err != nil {
		panic(err)
	}

	s.Listener = l

	log.Printf("listening on :%s\n", l.Addr().String())

	numTries := 0
	delay := s.Config.Delay

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			var nErr net.Error

			if errors.As(err, &nErr) {
				if nErr.Timeout() {
					if numTries >= s.Config.BackoffLimit {
						return fmt.Errorf("number of connection attempts has been exhausted: %w", err)
					}

					time.Sleep(time.Duration(delay) * time.Millisecond)

					delay += s.Config.DelayInc
					numTries++
				}
			} else {
				log.Printf("accept connection error: %s\n", err)
			}

			continue
		}

		numTries = 0
		delay = s.Config.Delay

		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	return s.Listener.Close()
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	a := auth.NewAuth(conn, s.Config.Credentials)

	if err := a.Authenticate(); err != nil {
		log.Println(err)
	}
}

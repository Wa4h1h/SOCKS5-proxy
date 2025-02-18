package proxy

import (
	"net"

	"github.com/Wa4h1h/SOCKS5-proxy/credentials"
	"github.com/Wa4h1h/SOCKS5-proxy/utils"
)

var DefaultServerConfig = ServerConfig{
	Delay:        utils.DefaultDelay,
	DelayInc:     utils.DefaultDelayInc,
	BackoffLimit: utils.DefaultBackoffLimit,
}

type ServerConfigOpt func(*ServerConfig)

type ServerConfig struct {
	Delay        int
	DelayInc     int
	BackoffLimit int
	Credentials  credentials.Credentials
}
type Server struct {
	Config   *ServerConfig
	Listener net.Listener
}

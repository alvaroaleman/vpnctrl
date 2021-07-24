package types

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alvaroaleman/vpnctrl/pkg/ini"
)

type WireguardConfig struct {
	Interface WireguardInterface `ini:"Interface"`
	Peer      WireguardPeer      `ini:"Peer"`
}

type WireguardInterface struct {
	PrivateKey       wgtypes.Key `ini:"-"`
	PrivateKeyString string      `ini:"PrivateKey"`
	Address          string      `ini:"Address"`
	ListenPort       int         `ini:"ListenPort,omitempty"`
	Table            string      `ini:"Table,omitempty"`
	PostUp           string      `ini:"PostUp,omitempty"`
	PostDown         string      `ini:"PostDown,omitempty"`
}

type WireguardPeer struct {
	PublicKey           wgtypes.Key `ini:"-"`
	PublicKeyString     string      `ini:"PublicKey"`
	Endpoint            string      `ini:"Endpoint,omitempty"`
	AllowedIPs          string      `ini:"AllowedIPs"`
	PersistentKeepAlive int         `ini:"PersistentKeepAlive,omitempty"`
}

func (wgcfg *WireguardConfig) MarshalIni() ([]byte, error) {
	wgcfg.Interface.PrivateKeyString = wgcfg.Interface.PrivateKey.String()
	wgcfg.Peer.PublicKeyString = wgcfg.Peer.PublicKey.String()
	type wgcfgMirror WireguardConfig
	wgCfgMirrored := wgcfgMirror(*wgcfg)
	return ini.Marshal(&wgCfgMirrored)
}

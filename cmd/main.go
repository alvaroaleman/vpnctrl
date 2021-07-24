package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/digitalocean/godo"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alvaroaleman/vpnctrl/pkg/ini"
	"github.com/alvaroaleman/vpnctrl/types"
)

type options struct {
	interfaceName string
}

func main() {
	log, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("failed to construct logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("failed to get hostname", zap.Error(err))
	}

	doClient := godo.NewFromToken(os.Getenv("DO_TOKEN"))

	localCfg, serverPrivKey, err := generateLocalConfig()
	if err != nil {
		log.Fatal("failed to generate wireguard config", zap.Error(err))
	}

	serverAddr, err := createServer(context.Background(), doClient, serverPrivKey, localCfg.Interface.PrivateKey.PublicKey(), hostname)
	if err != nil {
		log.Fatal("failed to create server", zap.Error(err))
	}
	log.Info("Created server", zap.String("address", serverAddr))

	localCfg.Peer.Endpoint = serverAddr + ":51820"
	localCfgSerialized, err := ini.Marshal(localCfg)
	if err != nil {
		log.Fatal("failed to marshal local wireguard config", zap.Error(err))
	}

	if err := ioutil.WriteFile("/etc/wireguard/"+hostname+".conf", localCfgSerialized, 0600); err != nil {
		log.Fatal("failed to write local wireguard config", zap.Error(err), zap.String("path", "/etc/wireguard/"+hostname+".conf"), zap.String("config", string(localCfgSerialized)))
	}
}

func generateLocalConfig() (cfg *types.WireguardConfig, serverPriv *wgtypes.Key, err error) {
	serverPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the private key for the server: %w", err)
	}
	clientPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the private key for the client: %w", err)
	}
	return &types.WireguardConfig{
		Interface: types.WireguardInterface{
			PrivateKey: clientPrivKey,
			Address:    "172.18.6.2/24",
			Table:      "off",
		},
		Peer: types.WireguardPeer{
			PublicKey:           serverPrivKey.PublicKey(),
			AllowedIPs:          "0.0.0.0/0",
			PersistentKeepAlive: 15,
		},
	}, &serverPrivKey, nil
}

func createServer(ctx context.Context, client *godo.Client, privKey *wgtypes.Key, clientKey wgtypes.Key, name string) (address string, err error) {
	wgCfg := types.WireguardConfig{
		Interface: types.WireguardInterface{
			Address:    "172.18.6.1/24",
			PrivateKey: *privKey,
			ListenPort: 51820,
			PostUp:     "echo 1 > /proc/sys/net/ipv4/ip_forward; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
			PostDown:   "iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
			Table:      "off",
		},
		Peer: types.WireguardPeer{
			PublicKey:  clientKey,
			AllowedIPs: "0.0.0.0/0",
		},
	}
	configBytes, err := ini.Marshal(&wgCfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal wireguard config: %w", err)
	}
	configBase64 := base64.StdEncoding.EncodeToString(configBytes)

	server, _, err := client.Droplets.Create(ctx, &godo.DropletCreateRequest{
		Name:    name,
		Region:  "fra1",
		Size:    "s-1vcpu-1gb",
		Image:   godo.DropletCreateImage{Slug: "ubuntu-20-04-x64"},
		SSHKeys: []godo.DropletCreateSSHKey{{Fingerprint: "23:2b:a6:6f:06:db:4e:04:fd:41:ca:99:98:f9:41:30"}},
		UserData: fmt.Sprintf(`#cloud-config
write_files:
- path: /etc/systemd/system/setup.service
  content: |
    [Unit]
    Description=Setup
    After=network-online.target
    Requires=network-online.target
    [Service]
    Type=oneshot
    RemainAfterExit=true
    ExecStart=/bin/bash -c 'set -euo pipefail; apt update && apt install -y wireguard wireguard-tools && wg-quick up wg0'
    [Install]
    RequiredBy=multi-user.target
- path: /etc/wireguard/wg0.conf
  encoding: b64
  content: %s
runcmd:
- systemctl enable --now setup.service
`, configBase64),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create server: %w", err)
	}

	timeAfterChan := time.After(30 * time.Second)
	id := server.ID
	for {
		select {
		case <-timeAfterChan:
			return "", errors.New("timed out waiting for server to be ready")
		default:
			server, _, err = client.Droplets.Get(ctx, id)
			if err != nil {
				return "", fmt.Errorf("failed to get droplet: %w", err)
			}
			if publicAddr := publicAddr(server); publicAddr != "" {
				return publicAddr, nil
			}
		}
	}

}

func publicAddr(server *godo.Droplet) string {
	for _, network := range server.Networks.V4 {
		if network.Type == "public" {
			return network.IPAddress
		}
	}

	return ""
}

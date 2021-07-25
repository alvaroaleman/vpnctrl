package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/digitalocean/godo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alvaroaleman/vpnctrl/pkg/ini"
	"github.com/alvaroaleman/vpnctrl/types"
)

const listenAddr = 51820

type options struct {
	interfaceName string
}

func main() {
	logCfg := zap.NewProductionConfig()
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	log, err := logCfg.Build()
	if err != nil {
		fmt.Printf("failed to construct logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("failed to get hostname", zap.Error(err))
	}
	if uid := os.Geteuid(); uid != 0 {
		log.Fatal("Must run as root, but ran with other UID", zap.Int("uid", uid))
	}

	doToken := os.Getenv("DO_TOKEN")
	if doToken == "" {
		log.Fatal("DO_TOKEN env var must be set and contain a valid DigitalOcean token")
	}
	doClient := godo.NewFromToken(doToken)

	localCfg, serverPrivKey, err := generateLocalConfig()
	if err != nil {
		log.Fatal("failed to generate wireguard config", zap.Error(err))
	}

	serverAddr, err := createServer(context.Background(), log, doClient, serverPrivKey, localCfg.Interface.PrivateKey.PublicKey(), hostname)
	if err != nil {
		log.Fatal("failed to create server", zap.Error(err))
	}
	log = log.With(zap.String("server_addr", serverAddr))
	log.Info("Created server and got its address")

	if err := waitForServer(log, serverAddr); err != nil {
		log.Fatal("Failed to wait for server to become reachable", zap.Error(err))
	}

	localCfg.Peer.Endpoint = serverAddr + ":" + strconv.Itoa(listenAddr)
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

func createServer(ctx context.Context,
	log *zap.Logger,
	client *godo.Client,
	privKey *wgtypes.Key,
	clientKey wgtypes.Key,
	name string,
) (address string, err error) {
	wgCfg := types.WireguardConfig{
		Interface: types.WireguardInterface{
			Address:    "172.18.6.1/24",
			PrivateKey: *privKey,
			ListenPort: listenAddr,
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
	log.Info("Successfully created server, waiting for IP to be assigned")

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

func waitForServer(log *zap.Logger, addr string) error {
	cfg := &ssh.ClientConfig{
		User:            "root",
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		cfg.Auth = append(cfg.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}

	log.Info("Waiting for wireguard server to become reachable")
	timeout := time.After(5 * time.Minute)
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to become reachable", addr)
		default:
			connection, err := ssh.Dial("tcp", addr+":22", cfg)
			if err != nil {
				log.Info("Error establishing ssh connection, retrying...", zap.Error(err))
				continue
			}
			session, err := connection.NewSession()
			if err != nil {
				return fmt.Errorf("failed to open ssh session: %w", err)
			}
			if err := session.Run("wg show wg0"); err != nil {
				log.Info("Wireguard server not yet up, retrying...")
				continue
			}

			log.Info("Wireguard server became reachable")
			return nil
		}
	}
}

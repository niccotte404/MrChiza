package config

import (
	"encoding/json"
	"os"
)

type ServerConfig struct {
	Listen         string `json:"listen"`
	PrivateKeyPath string `json:"private_key_path"`
	Destination    string `json:"destination"`
	SNI            string `json:"sni"`
	ChainDepth     int    `json:"chain_depth"`
	ProfilePath    string `json:"profile_path"`
	ProfileName    string `json:"profile_name"`
}

type ClientConfig struct {
	ServerAddress   string `json:"server_address"`
	ServerPublicKey string `json:"server_public_key"`
	SNI             string `json:"sni"`
	LocalListen     string `json:"local_listen"`
	ChainDepth      int    `json:"chain_depth"`
	ProfilePath     string `json:"profile_path"`
	ProfileName     string `json:"profile_name"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.ChainDepth == 0 {
		cfg.ChainDepth = 1
	}
	return &cfg, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.ChainDepth == 0 {
		cfg.ChainDepth = 1
	}
	return &cfg, nil
}

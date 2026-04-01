package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kubearmor/kubearmor-client/k8s"
	"github.com/kubearmor/kubearmor-client/utils"
)

func ConnectGrpc(c *k8s.Client, grpc string) (string, error) {
	if grpc != "" {
		return grpc, nil
	} else {
		if val, ok := os.LookupEnv("DISCOVERY_SERVICE"); ok {
			grpc = val
		} else {
			pf, err := utils.InitiatePortForward(c, Port, Port, MatchLabels, ServiceName)
			if err != nil {
				return "", err
			}
			grpc = "localhost:" + strconv.FormatInt(pf.LocalPort, 10)
		}
		return grpc, nil
	}
}

// GetDefaultConfigPath returns home dir along with an error
func GetDefaultConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if homeDir == "" {
		return "", fmt.Errorf("Home directory not found")
	}

	configPath := filepath.Join(homeDir, DefaultConfigPathDirName)

	return configPath, nil
}

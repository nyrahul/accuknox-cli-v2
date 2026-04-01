package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/accuknox/accuknox-cli-v2/pkg/common"
)

const policyDir = "/opt/kubearmor/policies"

type PolicyReader struct {
	Policies map[string]*KubeArmorPolicy
	mu       sync.Mutex
}

func NewPolicyReader() (*PolicyReader, error) {
	pr := &PolicyReader{
		Policies: make(map[string]*KubeArmorPolicy),
	}

	err := pr.ReadPolicies()
	return pr, err
}

func (pr *PolicyReader) ReadPolicies() error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	files, err := os.ReadDir(policyDir)
	if err != nil {
		return fmt.Errorf("failed to read policies from %s: %s", policyDir, err.Error())
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			fullPath := filepath.Join(policyDir, file.Name())
			policyJSON, err := common.CleanAndRead(fullPath)
			if err != nil {
				fmt.Printf("warning: failed to read policy file %s: %v\n", fullPath, err)
				continue
			}

			var policy KubeArmorPolicy
			err = policy.CustomUnmarshalJSON(policyJSON)
			if err != nil {
				fmt.Printf("warning: failed to unmarshal JSON policy %s: %v\n", fullPath, err)
				continue
			}

			if policy.Metadata.Name == "" {
				fmt.Printf("warning: policy name is empty for file %s\n", fullPath)
				continue
			}

			pr.Policies[policy.Metadata.Name] = &policy
		}
	}

	fmt.Printf("Total policies loaded: %d\n", len(pr.Policies)) // Debug log
	return nil
}

func (pr *PolicyReader) GetOptimizedPolicyYAML(name string) (string, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	policy, exists := pr.Policies[name]
	if !exists {
		return "", fmt.Errorf("policy not found: %s", name)
	}

	return policy.OptimizedYAML()
}

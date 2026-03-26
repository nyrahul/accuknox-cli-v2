//go:build windows

package vm

import "fmt"

var rraBinary []byte
var rra string = "rra-agent"
var fileName = "accuknox-%s_%s_result.json"

func PrepareRRACommand(profile, benchmark, authToken, label, url, tenantID, clusterName, clusterID string) []string {
	return nil
}

func ExecCommand(commandArgs []string, path, benchmark string, save bool) error {
	return fmt.Errorf("vm scan is not supported on Windows")
}

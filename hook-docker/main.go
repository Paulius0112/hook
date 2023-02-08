package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type tinkConfig struct {
	syslogHost         string
	insecureRegistries []string
}

type dockerConfig struct {
	Debug              bool              `json:"debug"`
	LogDriver          string            `json:"log-driver,omitempty"`
	LogOpts            map[string]string `json:"log-opts,omitempty"`
	InsecureRegistries []string          `json:"insecure-registries,omitempty"`
}

func main() {
	fmt.Println("Starting Tink-Docker")
	go rebootWatch()

	// Parse the cmdline in order to find the urls for the repository and path to the cert
	content, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		panic(err)
	}
	cmdLines := strings.Split(string(content), " ")
	cfg := parseCmdLine(cmdLines)
	
	err = os.MkdirAll("/etc/docker/certs.d/10.136.0.2:443", os.ModeDir)
        if err != nil {
                fmt.Println("Error creatin cert dir")
                panic(err)
        }

        credFile, credErr := os.Create("/etc/docker/certs.d/10.136.0.2:443/server.crt")
        fmt.Println("Adding server.crt file")
        if credErr != nil {
                        fmt.Println("Failed creating docker crt - debug")
                        panic(err)
        }

        fmt.Println("Docker crt created successfully")
        defer credFile.Close()

        fmt.Println("Adding custom docker cert - debug")
        d2 := []byte(`-----BEGIN CERTIFICATE-----
MIIFeTCCA2GgAwIBAgIUcJNyVobVtqjP+Ng64YEjQS34PUcwDQYJKoZIhvcNAQEN
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAyMDgxMzM1NDFaFw0zMzAy
MDUxMzM1NDFaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCzj7OsKRRXFn++IQeGkODFWXJb3SJz8L5P6eDCQNHV
IgfFfWazZ0kCBx9SmkTmOlU7SuaTJTwzyD1MWLMxDUb1aE9Yz7+jbo784ZOyCE1s
+dlff+wnY3qiM33XgTYOZrsSgiTLqmXKxb/aERKV3ohQyks8LFeJDW/7hc3dmtfp
5YR0zxk+WjzFAC4TF+o/jaHp/kr1lLfL2bBYWOCFf/S4k+E0Q0HmePlGpQ+htgj8
QZ2QuOeCIBSFN7gbcQU3JvY2ZhXPYcXXXnRKHCkDIpn1O1BTxgT7fXr9jfulnFXn
gdUPqQ+PiylHwKtxAKu4N6vAKsVubv4Z7Mj9rcOAGBBWjrPO7odeuVkobKv1UXSe
EndlqlWnlJ5hjg4+Pfh6btGsSAMCW/H/koeqtRlS3QAHuf0k2M8MGNRKIB5sDTDf
euAu9rLeRXT4FYlRUZRCcNveIwZVXRFD2/OGFzT+RGTNqc81fQh2VmbsK1GvkiuC
YprdkX3Y4s6xe/am//Ke9LW+IJQX4y5uH6guYqARZKYsYnBQodOImsYGFBbkfJa1
teH/9er06gD8dRkh/o4WKW/WHX43VT7Ssky7mp4+oaVJ/Iqm/QjXq0gHtDjGnlZf
Q7IGGzpf9/eRCejh8GZfqPyMi421dW0tQ04mAu4pFc8EIkt6aVxoZkuy+fYQydcb
QQIDAQABo2EwXzAfBgNVHSMEGDAWgBSvJYWyV6PMsVOvLppmf0zpRwB9gzAJBgNV
HRMEAjAAMAsGA1UdDwQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHREE
CDAGhwQKiAACMA0GCSqGSIb3DQEBDQUAA4ICAQAUOHcnHgLwcz5yOFDp9NIDe0OH
C1GSkSBd3WL7/2XsAAfYOV/nGpiWOvi+dv8SYxbiHbzozPPKpN8RSntGr6vIgkdD
gsaAuSC/qTZ2w65b90zte554Rag6WjBYYNGYILufWYYwZHwlm4NglSVJUhcGfv6p
ctev9vW779gFJyNgOrdeUoFrYkeAV3I7jOGqCXy7j26SXwk9AhPylcNoeL/rq0GD
ll0YVgurIa8ZcW9vsSdyoVJhRckmCYx2lISb+hTsenQJRbcG7dnSmUY9Gjyo4YzZ
lYm16McZzboHMwTWy9jNON4NqHiQDLhI1G7xSsuHVgyiehi7p82JTZMaIrtI1/wA
MZzqXT308fo6TFke24INAZMRlFpkQ5+uwu7PN72cXBZZjTEBNm9NGxZ6lAOjLI+H
n8DilLYNrzZ4lIEiPUmtIxQw93doqt6Lzht8sEdv009FqRcWMa2RCZqrxT8WKa6K
6pxTZpL3PfhG4OSZ78wJ5CuFTRRskZABkv+V6Xh9w5jgPh2RYCTBlvUqFj6QQ5Es
e6cS1Kwzr2X1aHEnmuhCE9BHNTyYB1ScySyEMYuY+AlKzmW9XgYAK1Xo7CGoFh0U
A9Q0xaEoMcoVpNGmI3Gp8ga2VEfeVs5UU9WAaEUiug3lFixRa+QqvEEaWh2H8FBP
YHPdIf6oF702iPqYlw==
-----END CERTIFICATE-----`)
        os.WriteFile("/etc/docker/certs.d/10.136.0.2:443/server.crt", d2, 0644)
        fmt.Println("Saved docker crt config")

	fmt.Println("Starting the Docker Engine")

	d := dockerConfig{
		Debug:     true,
		LogDriver: "syslog",
		LogOpts: map[string]string{
			"syslog-address": fmt.Sprintf("udp://%v:514", cfg.syslogHost),
		},
		InsecureRegistries: cfg.insecureRegistries,
	}
	path := "/etc/docker"
	// Create the directory for the docker config
	err = os.MkdirAll(path, os.ModeDir)
	if err != nil {
		panic(err)
	}
	if err := d.writeToDisk(filepath.Join(path, "daemon.json")); err != nil {
		panic(fmt.Sprintf("Failed to write docker config: %v", err))
	}

	// Build the command, and execute
	cmd := exec.Command("/usr/local/bin/docker-init", "/usr/local/bin/dockerd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}

// writeToDisk writes the dockerConfig to loc.
func (d dockerConfig) writeToDisk(loc string) error {
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("unable to marshal docker config: %w", err)
	}
	if err := os.WriteFile(loc, b, 0o600); err != nil {
		return fmt.Errorf("error writing daemon.json: %w", err)
	}

	return nil
}

// parseCmdLine will parse the command line.
func parseCmdLine(cmdLines []string) (cfg tinkConfig) {
	for i := range cmdLines {
		cmdLine := strings.Split(cmdLines[i], "=")
		if len(cmdLine) == 0 {
			continue
		}

		switch cmd := cmdLine[0]; cmd {
		case "syslog_host":
			cfg.syslogHost = cmdLine[1]
		case "insecure_registries":
			cfg.insecureRegistries = strings.Split(cmdLine[1], ",")
		}
	}
	return cfg
}

func rebootWatch() {
	fmt.Println("Starting Reboot Watcher")

	// Forever loop
	for {
		if fileExists("/worker/reboot") {
			cmd := exec.Command("/sbin/reboot")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				panic(err)
			}
			break
		}
		// Wait one second before looking for file
		time.Sleep(time.Second)
	}
	fmt.Println("Rebooting")
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

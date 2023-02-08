package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

type tinkConfig struct {
	// Registry configuration
	registry string
	username string
	password string

	// Tinkerbell server configuration
	baseURL    string
	tinkerbell string

	// Grpc stuff (dunno)
	grpcAuthority string

	// Worker ID(s) .. why are there two?
	workerID string
	ID       string

	// tinkWorkerImage is the Tink worker image location.
	tinkWorkerImage string

	// tinkServerTLS is whether or not to use TLS for tink-server communication.
	tinkServerTLS string
}

const maxRetryAttempts = 20

func main() {
	fmt.Println("Starting BootKit")

	// // Read entire file content, giving us little control but
	// // making it very simple. No need to close the file.

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

	// Generate the path to the tink-worker
	var imageName string
	if cfg.registry != "" {
		imageName = path.Join(cfg.registry, "tink-worker:latest")
	}
	if cfg.tinkWorkerImage != "" {
		imageName = cfg.tinkWorkerImage
	}
	if imageName == "" {
		// TODO(jacobweinstock): Don't panic, ever. This whole main function should ideally be a control loop that never exits.
		// Just keep trying all the things until they work. Similar idea to controllers in Kubernetes. Doesn't need to be that heavy though.
		panic("cannot pull image for tink-worker, 'docker_registry' and/or 'tink_worker_image' NOT specified in /proc/cmdline")
	}

	// Generate the configuration of the container
	tinkContainer := &container.Config{
		Image: imageName,
		Env: []string{
			fmt.Sprintf("DOCKER_REGISTRY=%s", cfg.registry),
			fmt.Sprintf("REGISTRY_USERNAME=%s", cfg.username),
			fmt.Sprintf("REGISTRY_PASSWORD=%s", cfg.password),
			fmt.Sprintf("TINKERBELL_GRPC_AUTHORITY=%s", cfg.grpcAuthority),
			fmt.Sprintf("TINKERBELL_TLS=%s", cfg.tinkServerTLS),
			fmt.Sprintf("WORKER_ID=%s", cfg.workerID),
			fmt.Sprintf("ID=%s", cfg.workerID),
		},
		AttachStdout: true,
		AttachStderr: true,
	}

	tinkHostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/worker",
				Target: "/worker",
			},
			{
				Type:   mount.TypeBind,
				Source: "/var/run/docker.sock",
				Target: "/var/run/docker.sock",
			},
		},
		NetworkMode: "host",
		Privileged:  true,
	}

	authConfig := types.AuthConfig{
		Username: cfg.username,
		Password: strings.TrimSuffix(cfg.password, "\n"),
	}

	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		panic(err)
	}

	authStr := base64.URLEncoding.EncodeToString(encodedJSON)

	pullOpts := types.ImagePullOptions{
		RegistryAuth: authStr,
	}

	// Give time to Docker to start
	// Alternatively we watch for the socket being created
	time.Sleep(time.Second * 3)
	fmt.Println("Starting Communication with Docker Engine")

	// Create Docker client with API (socket)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	fmt.Printf("Pulling image [%s]", imageName)

	// TODO: Ideally if this function becomes a loop that runs forever and keeps retrying
	// anything that failed, this retry would not be needed. For now, this addresses the specific
	// race condition case of when the linuxkit network or dns is in the process of, but not quite
	// fully set up yet.

	var out io.ReadCloser
	imagePullOperation := func() error {
		out, err = cli.ImagePull(ctx, imageName, pullOpts)
		if err != nil {
			fmt.Printf("Image pull failure %s, %v\n", imageName, err)
			return err
		}
		return nil
	}
	if err = backoff.Retry(imagePullOperation, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetryAttempts)); err != nil {
		panic(err)
	}

	if _, err = io.Copy(os.Stdout, out); err != nil {
		panic(err)
	}

	if err = out.Close(); err != nil {
		fmt.Printf("error closing io.ReadCloser out: %s", err)
	}

	resp, err := cli.ContainerCreate(ctx, tinkContainer, tinkHostConfig, nil, nil, "")
	if err != nil {
		panic(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
	}

	fmt.Println(resp.ID)
}

// parseCmdLine will parse the command line.
func parseCmdLine(cmdLines []string) (cfg tinkConfig) {
	for i := range cmdLines {
		cmdLine := strings.Split(cmdLines[i], "=")
		if len(cmdLine) == 0 {
			continue
		}

		switch cmd := cmdLine[0]; cmd {
		// Find Registry configuration
		case "docker_registry":
			cfg.registry = cmdLine[1]
		case "registry_username":
			cfg.username = cmdLine[1]
		case "registry_password":
			cfg.password = cmdLine[1]
		// Find Tinkerbell servers settings
		case "packet_base_url":
			cfg.baseURL = cmdLine[1]
		case "tinkerbell":
			cfg.tinkerbell = cmdLine[1]
		// Find GRPC configuration
		case "grpc_authority":
			cfg.grpcAuthority = cmdLine[1]
		// Find the worker configuration
		case "worker_id":
			cfg.workerID = cmdLine[1]
		case "tink_worker_image":
			cfg.tinkWorkerImage = cmdLine[1]
		case "tinkerbell_tls":
			cfg.tinkServerTLS = cmdLine[1]
		}
	}
	return cfg
}

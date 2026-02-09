// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Feeder structure holds the gRPC client and watchers
type Feeder struct {
	// Running indicates if watchers should continue
	Running bool

	// server address (e.g., "localhost:32767")
	server string

	// gRPC connection
	conn *grpc.ClientConn

	// gRPC client stub
	client pb.LogServiceClient

	// streams
	msgStream   pb.LogService_WatchMessagesClient
	alertStream pb.LogService_WatchAlertsClient
	logStream   pb.LogService_WatchLogsClient

	// wait group
	WgClient sync.WaitGroup
}

// NewClient dials the gRPC server (insecure) and sets up a Feeder.
func NewClient(server string) *Feeder {
	fd := &Feeder{
		Running: true,
		server:  server,
	}

	// Dial insecurely
	creds := insecure.NewCredentials()
	conn, err := grpc.Dial(fd.server, grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Printf("Failed to connect to a gRPC server (%s)\n", err.Error())
		return nil
	}
	fd.conn = conn
	fd.client = pb.NewLogServiceClient(fd.conn)

	return fd
}

// DestroyClient closes the connection and waits for watchers to finish.
func (fd *Feeder) DestroyClient() error {
	fd.Running = false
	if err := fd.conn.Close(); err != nil {
		return err
	}
	fd.WgClient.Wait()
	return nil
}

// DoHealthCheck pings the gRPC server with a random nonce.
func (fd *Feeder) DoHealthCheck() bool {
	nonceVal := rand.Int31()
	req := &pb.NonceMessage{Nonce: nonceVal}
	res, err := fd.client.HealthCheck(context.Background(), req)
	if err != nil {
		return false
	}
	return (res.Retval == nonceVal)
}

// WatchMessages streams KubeArmor Messages. Returns a channel of strings.
func (fd *Feeder) WatchMessages(jsonFormat bool) <-chan string {
	output := make(chan string)

	go func() {
		defer close(output)
		fd.WgClient.Add(1)
		defer fd.WgClient.Done()

		req := &pb.RequestMessage{Filter: ""}
		stream, err := fd.client.WatchMessages(context.Background(), req)
		if err != nil {
			fmt.Printf("Failed to call WatchMessages(): %s\n", err.Error())
			return
		}
		fd.msgStream = stream

		for fd.Running {
			res, err := fd.msgStream.Recv()
			if err != nil {
				fmt.Printf("Failed to receive a message: %s\n", err.Error())
				break
			}

			// Hack: We parse extra fields from the proto text representation.
			line := formatOutput(res, "Message", jsonFormat)
			output <- line
		}
	}()

	return output
}

// WatchAlerts streams KubeArmor Alerts. Returns a channel of strings.
func (fd *Feeder) WatchAlerts(jsonFormat bool) <-chan string {
	output := make(chan string)

	go func() {
		defer close(output)
		fd.WgClient.Add(1)
		defer fd.WgClient.Done()

		req := &pb.RequestMessage{Filter: "policy"} // or "all" if you want everything
		stream, err := fd.client.WatchAlerts(context.Background(), req)
		if err != nil {
			fmt.Printf("Failed to call WatchAlerts(): %s\n", err.Error())
			return
		}
		fd.alertStream = stream

		for fd.Running {
			res, err := fd.alertStream.Recv()
			if err != nil {
				fmt.Printf("Failed to receive an alert: %s\n", err.Error())
				break
			}

			line := formatOutput(res, "Alert", jsonFormat)
			output <- line
		}
	}()

	return output
}

// WatchLogs streams KubeArmor Logs. Returns a channel of strings.
func (fd *Feeder) WatchLogs(jsonFormat bool) <-chan string {
	output := make(chan string)

	go func() {
		defer close(output)
		fd.WgClient.Add(1)
		defer fd.WgClient.Done()

		req := &pb.RequestMessage{Filter: "system"} // or "all"
		stream, err := fd.client.WatchLogs(context.Background(), req)
		if err != nil {
			fmt.Printf("Failed to call WatchLogs(): %s\n", err.Error())
			return
		}
		fd.logStream = stream

		for fd.Running {
			res, err := fd.logStream.Recv()
			if err != nil {
				fmt.Printf("Failed to receive a log: %s\n", err.Error())
				break
			}
			// Minimal check: if Operation:"File" is in the text, skip
			protoText := fmt.Sprintf("%v", res)
			if strings.Contains(protoText, `Operation:"File"`) {
				continue
			}

			line := formatOutput(res, "Log", jsonFormat)
			output <- line
		}
	}()

	return output
}

// =========================== //
// == Hacky Extra Field Parse ==//
// =========================== //
//
// We parse those '20:"/usr/bin/bash"', '21:"/usr/bin/sleep"', etc.
// from the proto text representation, then add them to the final JSON.
//
// The user said, for example:
//  20:"/usr/bin/bash" => ParentProcessName
//  21:"/usr/bin/sleep" => ProcessName
//  22:38780 => HostPPID
//  25:"/home/ubuntu/" => Cwd
//  26:"pts2" => TTY
//
// We'll do it with a set of compiled regexes.

var (
	re20 = regexp.MustCompile(`\s20:"([^"]+)"`)
	re21 = regexp.MustCompile(`\s21:"([^"]+)"`)
	re22 = regexp.MustCompile(`\s22:(\d+)`)
	re25 = regexp.MustCompile(`\s25:"([^"]+)"`)
	re26 = regexp.MustCompile(`\s26:"([^"]+)"`)
)

// parseExtraFields finds these numeric keys in the proto text string
// and returns a map of extra field -> value.
func parseExtraFields(protoText string) map[string]string {
	extras := make(map[string]string)

	if match := re20.FindStringSubmatch(protoText); len(match) == 2 {
		extras["ParentProcessName"] = match[1]
	}
	if match := re21.FindStringSubmatch(protoText); len(match) == 2 {
		extras["ProcessName"] = match[1]
	}
	if match := re22.FindStringSubmatch(protoText); len(match) == 2 {
		extras["HostPPID"] = match[1]
	}
	if match := re25.FindStringSubmatch(protoText); len(match) == 2 {
		extras["Cwd"] = match[1]
	}
	if match := re26.FindStringSubmatch(protoText); len(match) == 2 {
		extras["TTY"] = match[1]
	}

	return extras
}

// formatOutput decides whether to pretty-print JSON or do a text-based output.
// It also calls parseExtraFields() to capture "20", "21", "22", etc., from the
// proto text representation and inject them into the final JSON or text.
func formatOutput(msg interface{}, recordType string, jsonFormat bool) string {
	// 1) Convert the proto message to text so we can parse numeric fields.
	msgText := fmt.Sprintf("%v", msg) // same as msg.String() if it's a proto
	extras := parseExtraFields(msgText)

	// 2) Convert the proto message to standard JSON (based on known proto fields).
	raw, _ := json.Marshal(msg)

	// 3) Unmarshal to a map so we can inject the extras.
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		// If parse fails, fallback
		return string(raw)
	}
	// Merge extras
	for k, v := range extras {
		obj[k] = v
	}

	// 4) If user wants JSON, do a pretty JSON output with the newly added fields.
	if jsonFormat {
		prettyBuf := &bytes.Buffer{}
		if err := json.Indent(prettyBuf, mustMarshal(obj), "", "  "); err != nil {
			return string(mustMarshal(obj))
		}
		return prettyBuf.String()
	}

	// 5) Otherwise produce a text-based output with all fields in order.
	return formatAsText(obj, recordType)
}

// formatAsText prints out the record in a text-based style.
func formatAsText(obj map[string]interface{}, recordType string) string {
	sb := &strings.Builder{}

	updatedTime, _ := obj["UpdatedTime"].(string)
	updatedTime = strings.Replace(updatedTime, "T", " ", -1)
	updatedTime = strings.Replace(updatedTime, "Z", "", -1)

	fmt.Fprintf(sb, "== %s / %s ==\n", recordType, updatedTime)

	// Known keys in a standard order
	telKeys := []string{
		"UpdatedTime", "Timestamp", "ClusterName", "HostName", "NamespaceName",
		"PodName", "Labels", "ContainerName", "ContainerID", "ContainerImage",
		"Type", "PolicyName", "Severity", "Message", "Source",
		"Resource", "Operation", "Action", "Data", "Enforcer",
		"Result", "Cwd", "TTY", "ParentProcessName", "ProcessName",
		"HostPPID", "PPID", "UID",
	}

	// Add any leftover fields
	var extraKeys []string
	for k := range obj {
		if !contains(telKeys, k) {
			extraKeys = append(extraKeys, k)
		}
	}
	sort.Strings(extraKeys)
	telKeys = append(telKeys, extraKeys...)

	for _, k := range telKeys {
		if k == "UpdatedTime" {
			// skip re-printing the time in the list
			continue
		}
		val, ok := obj[k]
		if !ok {
			continue
		}
		valStr := fmt.Sprintf("%v", val)
		if valStr != "" {
			fmt.Fprintf(sb, "%s: %s\n", k, valStr)
		}
	}
	return sb.String()
}

// mustMarshal is a helper to quickly turn an interface{} into JSON bytes.
func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// contains checks if slice has the given string
func contains(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}

// StrToFile writes a string to a file (used if you want to store logs).
func StrToFile(str, destFile string) {
	if _, err := os.Stat(destFile); err != nil {
		f, createErr := os.Create(filepath.Clean(destFile))
		if createErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to create file (%s): %s\n", destFile, createErr.Error())
			return
		}
		_ = f.Close()
	}
	f, err := os.OpenFile(destFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file (%s): %s\n", destFile, err.Error())
		return
	}
	defer f.Close()

	if _, err = f.WriteString(str + "\n"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write string to file (%s): %s\n", destFile, err.Error())
	}
}

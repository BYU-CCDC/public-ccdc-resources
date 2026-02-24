package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

type bytes_read_closer struct {
	*bytes.Reader
}

func NewBytesReadCloser(b []byte) *bytes_read_closer {
	ret := &bytes_read_closer{}
	ret.Reader = bytes.NewReader(b)
	return ret
}

func (_ bytes_read_closer) Close() error {
	return nil
}

func get_requests(data []byte) []*http.Request {
	b := bufio.NewReader(bytes.NewReader(data))

	requests := make([]*http.Request, 0, 16)

	for {
		req, err := http.ReadRequest(b)

		if req != nil {
			requests = append(requests, req)
			if req.Body != nil {
				// Ignoring body read errors won't bite me at all later
				body, _ := io.ReadAll(req.Body)
				req.Body = NewBytesReadCloser(body)
			}
		}

		if err != nil {
			return requests
		}
	}
}

// from https://github.com/corazawaf/coraza/blob/eaa5edfe4362870ee72d30a4436e23f3233e8c29/http/middleware.go#L27
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(req.Host)
	}

	// Transfer-Encoding header is removed by go/http
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %s", err.Error())
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			bodyReader := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			req.Body = io.NopCloser(bodyReader)
		}
	}

	return tx.ProcessRequestBody()
}
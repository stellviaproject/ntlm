package ntlm

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

func NewNTLMTransport(user, password, proxyURL, domain string) (*http.Transport, error) {
	if proxyURL == "" {
		return &http.Transport{}, nil
	}
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if password == "" || user == "" {
		return &http.Transport{
			Proxy: http.ProxyURL(proxy),
		}, nil
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	ntlmDialContext := WrapDialContext(dialer.DialContext, proxy.Host, user, password, domain)
	return &http.Transport{
		Dial:                  dialer.Dial,
		DialContext:           ntlmDialContext,
		TLSClientConfig:       &tls.Config{},
		MaxIdleConns:          20,
		ResponseHeaderTimeout: 30 * time.Second,
	}, nil
}

// DialContext is the DialContext function that should be wrapped with a
// NTLM Authentication.
//
// Example for DialContext:
//
// dialContext := (&net.Dialer{KeepAlive: 30*time.Second, Timeout: 30*time.Second}).DialContext
type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func NtlmDialContext(dialContext DialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain string) DialContext {
	authMsg := ""
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, proxyAddress)
		if err != nil {
			log.Printf("ntlm> Could not call dial context with proxy: %s\n\r", err)
			return conn, err
		}
		// NTLM Step 2: Receive Challenge Message
		br := bufio.NewReader(conn)
		// If it has authMsg no negociate
		header := make(http.Header)
		if authMsg == "" {
			// NTLM Step 1: Send Negotiate Message
			negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
			if err != nil {
				log.Printf("ntlm> Could not negotiate domain '%s': %s\n\r", proxyDomain, err)
				return conn, err
			}
			log.Printf("ntlm> NTLM negotiate message: '%s'\n\r", base64.StdEncoding.EncodeToString(negotiateMessage))
			header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(negotiateMessage)))
			header.Set("Proxy-Connection", "Keep-Alive")
			connect := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: header,
			}
			if err := connect.Write(conn); err != nil {
				log.Printf("ntlm> Could not write negotiate message to proxy: %s\n\r", err)
				return conn, err
			}
			log.Printf("ntlm> Successfully sent negotiate message to proxy\n\r")
			resp, err := http.ReadResponse(br, connect)
			if err != nil {
				log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
				return conn, err
			}
			_, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("ntlm> Could not read response body from proxy: %s\n\r", err)
				return conn, err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusProxyAuthRequired {
				log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusProxyAuthRequired, resp.StatusCode)
				return conn, errors.New(http.StatusText(resp.StatusCode))
			}
			challenge := strings.Split(resp.Header.Get("Proxy-Authenticate"), " ")
			if len(challenge) < 2 {
				log.Printf("ntlm> The proxy did not return an NTLM challenge, got: '%s'", resp.Header.Get("Proxy-Authenticate"))
				return conn, errors.New("no NTLM challenge received")
			}
			log.Printf("ntlm> NTLM challenge: '%s'\n\r", challenge[1])
			challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
			if err != nil {
				log.Printf("ntlm> Could not base64 decode the NTLM challenge: %s\n\r", err)
				return conn, err
			}
			// NTLM Step 3: Send Authorization Message
			log.Printf("ntlm> Processing NTLM challenge with username '%s' and password with length %d\n\r", proxyUsername, len(proxyPassword))
			authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, proxyDomain != "")
			if err != nil {
				log.Printf("ntlm> Could not process the NTLM challenge: %s\n\r", err)
				return conn, err
			}
			authMsg = base64.StdEncoding.EncodeToString(authenticateMessage)
		}
		log.Printf("ntlm> NTLM authorization: '%s'\n\r", authMsg)
		header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", authMsg))
		connect := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		if err := connect.Write(conn); err != nil {
			log.Printf("ntlm> Could not write authorization to proxy: %s\n\r", err)
			return conn, err
		}
		resp, err := http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusOK, resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}
		// Succussfully authorized with NTLM
		log.Printf("ntlm> Successfully injected NTLM to connection\n\r")
		return conn, nil
	}
}

// WrapDialContext wraps a DialContext with an NTLM Authentication to a proxy.
func WrapDialContext(dialContext DialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain string) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, proxyAddress)
		if err != nil {
			log.Printf("ntlm> Could not call dial context with proxy: %s\n\r", err)
			return conn, err
		}
		// NTLM Step 1: Send Negotiate Message
		negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
		if err != nil {
			log.Printf("ntlm> Could not negotiate domain '%s': %s\n\r", proxyDomain, err)
			return conn, err
		}
		log.Printf("ntlm> NTLM negotiate message: '%s'\n\r", base64.StdEncoding.EncodeToString(negotiateMessage))
		header := make(http.Header)
		header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(negotiateMessage)))
		header.Set("Proxy-Connection", "Keep-Alive")
		connect := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		if err := connect.Write(conn); err != nil {
			log.Printf("ntlm> Could not write negotiate message to proxy: %s\n\r", err)
			return conn, err
		}
		log.Printf("ntlm> Successfully sent negotiate message to proxy\n\r")
		// NTLM Step 2: Receive Challenge Message
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("ntlm> Could not read response body from proxy: %s\n\r", err)
			return conn, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusProxyAuthRequired, resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}
		challenge := strings.Split(resp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			log.Printf("ntlm> The proxy did not return an NTLM challenge, got: '%s'", resp.Header.Get("Proxy-Authenticate"))
			return conn, errors.New("no NTLM challenge received")
		}
		log.Printf("ntlm> NTLM challenge: '%s'\n\r", challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			log.Printf("ntlm> Could not base64 decode the NTLM challenge: %s\n\r", err)
			return conn, err
		}
		// NTLM Step 3: Send Authorization Message
		log.Printf("ntlm> Processing NTLM challenge with username '%s' and password with length %d\n\r", proxyUsername, len(proxyPassword))
		authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, proxyDomain != "")
		if err != nil {
			log.Printf("ntlm> Could not process the NTLM challenge: %s\n\r", err)
			return conn, err
		}
		log.Printf("ntlm> NTLM authorization: '%s'\n\r", base64.StdEncoding.EncodeToString(authenticateMessage))
		header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		connect = &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		if err := connect.Write(conn); err != nil {
			log.Printf("ntlm> Could not write authorization to proxy: %s\n\r", err)
			return conn, err
		}
		resp, err = http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusOK, resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}
		// Succussfully authorized with NTLM
		log.Printf("ntlm> Successfully injected NTLM to connection\n\r")
		return conn, nil
	}
}

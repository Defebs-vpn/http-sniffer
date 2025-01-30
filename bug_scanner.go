package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Fungsi untuk memeriksa status HTTP dari URL
func checkStatus(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Gagal mengakses %s: %s\n", url, err)
		return
	}
	defer resp.Body.Close()

	// Memeriksa status HTTP response
	if resp.StatusCode != 200 {
		fmt.Printf("Peringatan: %s mengembalikan status %d\n", url, resp.StatusCode)
	} else {
		fmt.Printf("URL %s aman (Status: %d)\n", url, resp.StatusCode)
	}
}

// Fungsi untuk memeriksa keberadaan header keamanan pada HTTP Response
func checkSecurityHeaders(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Gagal mengakses %s: %s\n", url, err)
		return
	}
	defer resp.Body.Close()

	headers := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Content-Security-Policy",
		"X-XSS-Protection",
	}

	fmt.Printf("Memeriksa header keamanan pada %s...\n", url)
	for _, header := range headers {
		if val := resp.Header.Get(header); val == "" {
			fmt.Printf("Peringatan: Header %s tidak ditemukan\n", header)
		} else {
			fmt.Printf("Header %s ditemukan: %s\n", header, val)
		}
	}
}

func main() {
	urls := []string{
		"http://example.com",
		"http://another-example.com",
		// Tambahkan URL lain yang ingin dipindai
	}

	for _, url := range urls {
		checkStatus(url)
		checkSecurityHeaders(url)
	}
}

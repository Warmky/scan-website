package discover

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func GuessMailServer(domain string, timeout time.Duration, maxConcurrency int) []string {
	prefixMap := map[string][]string{
		"SMTP": {"smtp.", "smtps.", "mail.", "submission.", "mx."},
		"IMAP": {"imap.", "imap4.", "imaps.", "mail.", "mx."},
		"POP":  {"pop.", "pop3.", "pop3s.", "mail.", "mx."},
	}

	portMap := map[string][]int{
		"SMTP": {465, 587},
		"IMAP": {143, 993},
		"POP":  {110, 995},
	}

	var results []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, maxConcurrency) // 控制最大并发数

	for proto, prefixes := range prefixMap {
		for _, port := range portMap[proto] {
			for _, prefix := range prefixes {
				wg.Add(1)
				go func(host string, port int) {
					defer wg.Done()
					semaphore <- struct{}{}        // 获取令牌
					defer func() { <-semaphore }() // 释放令牌

					conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
					if err == nil {
						conn.Close()
						mu.Lock()
						results = append(results, fmt.Sprintf("%s:%d", host, port))
						mu.Unlock()
					}
				}(prefix+domain, port)
			}
		}
	}

	wg.Wait()
	return results
}

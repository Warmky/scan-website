package utils

import "net/http"

// http查询相关函数
func GetRedirects(resp *http.Response) (history []map[string]interface{}) {
	for resp != nil {
		req := resp.Request
		status := resp.StatusCode
		entry := map[string]interface{}{
			"URL":    req.URL.String(),
			"Status": status,
		}
		history = append(history, entry)
		resp = resp.Request.Response
	}
	if len(history) >= 1 {
		for l, r := 0, len(history)-1; l < r; l, r = l+1, r-1 {
			history[l], history[r] = history[r], history[l]
		}
	}
	return history
}

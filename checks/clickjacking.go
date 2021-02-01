package checks

import "strings"

// TODO
func allowsIframes(headers map[string]interface{}) bool {
	for k, v := range headers {
		keyLower := strings.ToLower(k)
		headers[keyLower] = v
	}

	if _, ok := headers["x-frame-options"]; ok {
		if headers["x-frame-options"].(string) == "DENY" || headers["x-frame-options"].(string) == "SAMEORIGIN" {
			return false
		}
		if strings.Contains(headers["content-security-policy"].(string), "frame-src") {
			return false
		}
	}

	return true
}

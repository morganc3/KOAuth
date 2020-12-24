package checks

import "log"

var Mappings map[string]CheckFunction

// mappings of check names from JSON to functions
func getMappings() map[string]CheckFunction {
	return map[string]CheckFunction{
		"redirect-uri-total-change":     RedirectURITotalChange,
		"redirect-uri-scheme-downgrade": RedirectURISchemeDowngrade,
		"state-supported":               StateSupported,
		"pkce-supported":                PkceSupported,
	}
}

func getMapping(name string) CheckFunction {
	if v, ok := Mappings[name]; ok {
		return v
	}
	log.Fatalf("Check name %s does not map to function in checks/mapping.go", name)
	return nil
}

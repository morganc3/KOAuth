package checks

var mappings map[string]customCheckFunction

// mappings of check names from JSON to functions
// these are mappings of custom check functions
// for checks that can't be accomplished with the
// simple model defined in our checks.json structure/templating
func getMappings() map[string]customCheckFunction {
	return map[string]customCheckFunction{
		"clickjacking-in-oauth-handshake": clickjackingCheck,
	}
}

func getMapping(name string) customCheckFunction {
	if v, ok := mappings[name]; ok {
		return v
	}
	return nil
}

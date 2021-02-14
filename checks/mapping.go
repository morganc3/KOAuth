package checks

var Mappings map[string]CustomCheckFunction

// mappings of check names from JSON to functions
// these are mappings of custom check functions
// for checks that can't be accomplished with the
// simple model defined in our checks.json structure/templating
func getMappings() map[string]CustomCheckFunction {
	return map[string]CustomCheckFunction{
		"clickjacking-in-oauth-handshake": ClickjackingCheck,
	}
}

func getMapping(name string) CustomCheckFunction {
	if v, ok := Mappings[name]; ok {
		return v
	}
	return nil
}

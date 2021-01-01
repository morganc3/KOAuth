package checks

var Mappings map[string]CheckFunction

// mappings of check names from JSON to functions
// these are mappings of custom check functions
// for checks that can't be accomplished with the
// simple model defined in our checks.json structure/templating
func getMappings() map[string]CheckFunction {
	return map[string]CheckFunction{}
}

func getMapping(name string) CheckFunction {
	if v, ok := Mappings[name]; ok {
		return v
	}
	return nil
}

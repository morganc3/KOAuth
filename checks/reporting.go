package checks

// structs for output format

type StepOut struct {
	//fields taken from Step.FlowInstance
	AuthorizationURL string `json:"authorizationURL"`
	RedirectedToURL  string `json:"redirectedToURL"`

	FailMessage  string `json:"failMessage,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`

	RequiredOutcome string `json:"requiredOutcome"`

	FlowType string `json:"flowType,omitempty"`

	// State contains result of the step
	State `json:"state"`
}

type CheckOut struct {
	CheckName    string    `json:"name"`
	RiskRating   string    `json:"risk"`
	Description  string    `json:"description"`
	SkipReason   string    `json:"skipReason,omitempty"`
	References   string    `json:"references,omitempty"`
	FailMessage  string    `json:"failMessage,omitempty"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
	Steps        []StepOut `json:"steps,omitempty"`
	State        `json:"state"`
}

// convert Step to StepOut
func (s *Step) Export() StepOut {
	return StepOut{
		AuthorizationURL: s.FlowInstance.AuthorizationURL.String(),
		RedirectedToURL:  s.FlowInstance.RedirectedToURL.String(),
		FailMessage:      s.FailMessage,
		ErrorMessage:     s.ErrorMessage,
		RequiredOutcome:  s.RequiredOutcome,
		State:            s.State,
		FlowType:         s.FlowType,
	}
}

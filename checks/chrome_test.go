package checks

import (
	"fmt"
	"testing"

	"github.com/morganc3/KOAuth/browser"
	"github.com/stretchr/testify/assert"
)

func TestCustomChromeChecks(t *testing.T) {
	h, _ := browser.Load("http://example.com/")

	allowed := allowsIframes(*h)
	assert.Equal(t, allowed, true)

	h, _ = browser.Load("http://google.com/")
	fmt.Println(h)
	allowed = allowsIframes(*h)
	assert.Equal(t, allowed, false)

}

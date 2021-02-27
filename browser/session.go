package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
)

// ChromeExecContext - Original parent chrome tab context
var ChromeExecContext context.Context

// ChromeExecContextCancel - Original parent chrome tab context cancel function
var ChromeExecContextCancel context.CancelFunc

// RunWithTimeOut - run chromedp actions with a specified timeout
func RunWithTimeOut(ctx *context.Context, timeout time.Duration, actions []chromedp.Action) (context.Context, error) {
	timeoutContext, _ := context.WithTimeout(*ctx, timeout*time.Second)
	// defer timeoutCancel()
	return timeoutContext, chromedp.Run(timeoutContext, actions...)
}

// InitChromeSession - initialize chrome session, setting
// options from CLI
func InitChromeSession() context.CancelFunc {
	var chromeOpts []chromedp.ExecAllocatorOption
	headlessFlag := chromedp.Flag("headless", false)
	userAgentFlag := chromedp.UserAgent(config.GetOpt(config.FlagUserAgent))
	chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:], headlessFlag, userAgentFlag)

	proxy := config.GetOpt(config.FlagProxy)
	if proxy != "" {
		// Be sure you trust your proxy server if you choose this option
		ignoreCerts := chromedp.Flag("ignore-certificate-errors", true)
		chromeOpts = append(chromeOpts,
			chromedp.ProxyServer(proxy),
			ignoreCerts,
		)
	}
	cx, cancel := chromedp.NewExecAllocator(context.Background(), chromeOpts...)
	ChromeExecContext = cx
	ChromeExecContextCancel = cancel
	return cancel
}

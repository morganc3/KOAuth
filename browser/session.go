package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
)

var ChromeExecContext context.Context
var ChromeExecContextCancel context.CancelFunc

func RunWithTimeOut(ctx *context.Context, timeout time.Duration, actions []chromedp.Action) (context.Context, error) {
	timeoutContext, _ := context.WithTimeout(*ctx, timeout*time.Second)
	return timeoutContext, chromedp.Run(timeoutContext, actions...)
}

func InitChromeSession() context.CancelFunc {
	var chromeOpts []chromedp.ExecAllocatorOption
	headlessFlag := chromedp.Flag("headless", false)
	userAgentFlag := chromedp.UserAgent(config.GetOpt(config.FLAG_USER_AGENT))
	chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:], headlessFlag, userAgentFlag)

	proxy := config.GetOpt(config.FLAG_PROXY)
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

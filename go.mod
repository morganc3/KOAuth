module github.com/morganc3/KOAuth

go 1.13

require (
	github.com/chromedp/cdproto v0.0.0-20200709115526-d1f6fc58448b
	github.com/chromedp/chromedp v0.5.4-0.20200729192944-ccb1bb06c868
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/gobwas/httphead v0.0.0-20200921212729-da3d93bc3c58 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.0.4 // indirect
	github.com/hoisie/mustache v0.0.0-20160804235033-6375acf62c69
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/ogier/pflag v0.0.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20200904194848-62affa334b73
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f // indirect
	honnef.co/go/tools v0.0.1-2020.1.4
)

replace golang.org/x/oauth2 => github.com/morganc3/oauth2 v0.1.12

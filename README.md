# KOAuth
OAuth 2.0 automated security scanner
Work in progress!

OAuth 2.0 is difficult to create a re-usable dynamic scanner because the OAuth 2.0 specification allows redirects to be implemented using any method available to the user agent. This means you cannot simply look for a 3XX status code. 
For this reason, this scanner uses `chromedp` to run the checks in a browser environment. 

Additionally, OAuth authorization servers often diverge from the spec in small but 
frustrating ways. For example, requiring consent to be obtained each time a user 
attempts to perform an OAuth 2.0 flow, even if they have already consented and authenticated 
previously. 

This scanner attempts to provide configuration/CLI options to address these common scenarios. 

The scanner works by:

1. Running `chromedp` and having the user authenticate at an OAuth 2.0 Auth URL
2. Once a user's session is established, opens new tabs in the Chrome browser and runs 
various checks

Usage:
- Place OAuth 2.0 credentials/information in config.json
- `go build`
- `./KOAuth --config configfile.json --checks ./config/resources/checks.json --timeout 4`

The timeout option defines how long each tab will wait to be redirected to the redirect_uri 
before assuming the request failed. 
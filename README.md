# KOAuth
OAuth 2.0 automated security scanner
Work in progress!

The scanner works by:

1. Running an electron app, where the user browses to the provided 
URL in the `--config` file and logs in
2. The electron app then saves session information (currently Cookies+LocalStorage) to session.json
3. Go program runs, performing OAuth checks. `chromedp` is used to emulate a browser, 
in order to support various edge cases such as OAuth redirects using JavaScript rather than 3XX responses.

TODO: Support indexedb

Usage:
- Place OAuth 2.0 credentials/information in config.json
- `cd electron`
- `npm start # starts electron app, which will set session information at KOAuth/session.json` 
- `go build`
- `./KOAuth --config configfile.json`

./KOAuth --config config_discord.json --session session_discord.json
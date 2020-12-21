const { app, BrowserWindow } = require('electron')
const jsonfile = require('jsonfile')
const file = '../config.json'

var url = ""


function init() {
    // read config and open browser
    jsonfile.readFile(file)
        .then(obj => createWindow(obj))
        .catch(error => console.error(error))
}

function generateAuthUrl(conf){
    url = conf.endpoint.auth_url;
    url += "?redirect_uri=" + encodeURI(conf.redirect_url);
    url += "&client_id=" + conf.client_id;
    url += "&scope=";
    conf.scopes.forEach(function (item, index) {
	url += encodeURI(item) + "+";
    });

    url = url.substring(0, url.length - 1);
    url += "&state=RANDOM";
    url += "&response_type=token";
    return url;
}

function saveSessionAndExit(ses){
    let cookies = ses.cookies;
    cookies.get({ url: url }).then((cookies) => {
        console.log(cookies)
    }).catch((error) => {
        console.log(error)
    });
    process.exit(1)
}


function createWindow(conf){
    url = generateAuthUrl(conf);
    
    const win = new BrowserWindow({ width: 800, height: 600 })
    win.loadURL(url,{userAgent: 'Chrome'})

    const ses = win.webContents.session
    ses.webRequest.onBeforeRequest((details, callback) => {
	//console.log("Making request to "+details.url);
	// figure out when we're getting sent to redirect uri and intercept
	// then write cookies + local storage to session file
	var currUrl = new URL(details.url);
	var confUrl = new URL(conf.redirect_url);

	if (currUrl.host + currUrl.path === confUrl.host + confUrl.path) {
	    saveSessionAndExit(ses);
	}
	callback({ requestHeaders: details.requestHeaders})
    })
}

app.on("ready", init);

app.on('window-all-closed', () => {
  app.quit()
})

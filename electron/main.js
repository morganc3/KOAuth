const { app, BrowserWindow } = require('electron')
const jsonfile = require('jsonfile')
const file = '../config.json'

var url = ""


function readConfig() {
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

function createWindow(obj){
    url = generateAuthUrl(obj);
    
    const win = new BrowserWindow({ width: 800, height: 600 })
    win.loadURL(url)

    const ses = win.webContents.session
    ses.webRequest.onBeforeRequest((details, callback) => {
	//console.log("Making request to "+details.url);
	// figure out when we're getting sent to redirect uri and intercept
	// then write cookies + local storage to session file
	callback({ requestHeaders: details.requestHeaders})
    })

    let cookies = ses.cookies;
    cookies.get({ url: url }).then((cookies) => {
	console.log(cookies)
    }).catch((error) => {
	console.log(error)
    });
}

app.on("ready", readConfig);

app.on('window-all-closed', () => {
  app.quit()
})

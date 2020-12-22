const { app, BrowserWindow } = require('electron')
const jsonfile = require('jsonfile')

const configFile = '../config.json'
const sessionFile = '../session.json'

var url = ""

// TODO: make configurable
let clearCache = true

function init() {
    // read config and open browser
    jsonfile.readFile(configFile)
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

// write cookies and local storage to session file
// TODO: Add support for indexedDB, etc
function saveSessionAndExit(win, ses){
    let cookies = ses.cookies;

    let sessionObject = {}

    // get cookies
    let promise1 = cookies.get({ url: url }).then((cookies) => {
        sessionObject.cookies = cookies;
    }).catch((error) => {
        console.log(error)
    });

    // Get localstorage
    let promise2 = win.webContents.executeJavaScript(`
        let localStorageArr = []; 
        let localStorageKeys = Object.keys(localStorage); 
        localStorageKeys.forEach((item) => localStorageArr.push({"name":item, "value":localStorage.getItem(item)}));
        Promise.resolve(localStorageArr)`, 
        true)
        .then((result) => {
            sessionObject.localStorage = result;
        }).catch((error) => {
            console.log(error)
        });

    // wait until promises are all resolved and write to session file
    Promise.all([promise1, promise2]).then(() => jsonfile.writeFile(sessionFile, sessionObject)
        .then(res => {
            console.log("Wrote session information to " + sessionFile);
            app.quit();
        })
        .catch(error => console.error(error)));
}

function createWindow(conf){
    url = generateAuthUrl(conf);
    
    const win = new BrowserWindow({ width: 800, height: 600 })
    const ses = win.webContents.session

    win.loadURL(url,{userAgent: 'Chrome'})

    ses.webRequest.onBeforeRequest((details, callback) => {
        // figure out when we're getting sent to redirect uri and intercept
        // then write cookies + local storage to session file
        var currUrl = new URL(details.url);
        var confUrl = new URL(conf.redirect_url);

        if (currUrl.host + currUrl.path === confUrl.host + confUrl.path) {
            saveSessionAndExit(win, ses);
        }
        callback({ requestHeaders: details.requestHeaders})
    })
}

app.on("ready", init);

app.on('window-all-closed', () => {
  app.quit()
})

const express = require('express')
const nunjucks = require("nunjucks")
const bodyParser = require('body-parser');
const fs = require("fs")
const config = require("./config.js")
const child = require("node:child_process")
const app = express()
const port = 3000
const pam = require('authenticate-pam');

nunjucks.configure('views', {
    autoescape: true,
    express: app,
    noCache: true
});

global.tokens = {

}

app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.sendFile(`${__dirname}/views/index.html`)
})

app.get('/oauth2/authorize', (req, res, next) => {
    var { client_id, response_type, state, scope } = req.query
    var end
    if (!scope) scope = "openid profile"
    const scopes = scope.split(" ")
    if (!scopes.includes("profile")) scopes.push("profile")
    if (response_type && response_type !== "code") return res.send("Only the code response type is supported.").status(400)
    const app = config.applications[client_id]
    scopes.forEach(scope => {
        if (!app.scopes.includes(scope)) {
            res.send(`Scope not approved: ${scope}`)
            end = true
        }
    })
    if (end) return
    if (!app) return res.send("Application not found").status(400)
    console.log(scopes)
    res.render("login.html", {
        ...app, state, client_id, scopes, scope
    })
})


app.post('/oauth2/validate', (req, res) => {
    var { username, password, redirect_uri, state, client_id, scope } = req.body
    if (!scope) scope = "openid profile"
    const scopes = scope.split(" ")
    if (!scopes.includes("profile")) scopes.push("profile")
var end
    const app = config.applications[client_id]
    scopes.forEach(scope => {
        if (!app.scopes.includes(scope)) {
            res.send(`Scope not approved: ${scope}`)
            end = true
        }
    })
    if (end) return
    pam.authenticate(username, password, function (error) {
        if (error) return res.send("Wrong credentials").status(401)
        else {
            const code = Math.random().toString(32).slice(2)
            const id = child.execSync(`id -u "${username}"`).toString().replace("\n", "").toLowerCase()
            const groups = child.execSync(`groups "${username}" 2>/dev/null`).toString().split(" : ")[1].split(" ").map(group => group.replace("\n", "").toLowerCase())
            console.log(global.tokens)
            global.tokens[code] = {
                username, client_id, id, groups
            }
            if (scopes.includes("email")) {
                const email = child.execSync(`ldapsearch -H ${config.ldap.hostname} -b dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -D cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -w '${config.ldap.password}' -LLL -o ldif-wrap=no '(cn=david)' 'mail' | grep mail: | cut -d' ' -f2`).toString()
                global.tokens[code].email = email
            } else {
                global.tokens[code].email = `${username}@hackclub.app`
            }
            return res.redirect(`${redirect_uri}?${new URLSearchParams({
                state, code
            })}`)
        }
    });
})

app.post('/oauth2/token', (req, res) => {
    const { client_id, client_secret } = req.body
    var token = ""
    if (req.body.token) token = req.body.token
    else if (req.body.code) token = req.body.code
    else return res.send("Token not found").status(400)

    console.log(req.body)
    const app = config.applications[client_id]
    if (!app) return res.send("Application not found").status(400)

    if (client_secret != app.clientSecret) return res.send("Incorrect client secret").status(401)
    console.log(global.tokens)
    if (!global.tokens[token] || !global.tokens[token].client_id == client_id) return res.send("Token not found").status(400)

    res.json({
        access_token: token,
        refresh_token: token,
        token_type: "Bearer",
        expires: 10
    })
})

app.get('/oauth2/profile', (req, res) => {
    const auth = req.headers.authorization
    if (!auth.includes("Bearer ")) return res.send("Not bearer authorization.").status(400)
    const profile = global.tokens[auth.replace("Bearer ", "")]
    if (!profile) return res.send("Token expired or non-existant").status(401)
    res.json(profile)
})

app.get('/.well-known/openid-configuration', (req, res) => {
    res.sendFile(`${__dirname}/openid.json`)
})

app.listen(process.env.PORT || port, () => {
    console.log(`Example app listening on port ${port}`)
})


const express = require('express')
const nunjucks = require("nunjucks")
const bodyParser = require('body-parser');
const fs = require("fs")
const config = require("./config.js")
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

app.get('/oauth2/authorize', (req, res) => {
    const { client_id, response_type, state, scope } = req.query
    if (response_type && response_type !== "code") return res.send("Only the code response type is supported.").status(400)
    const app = config.applications[client_id]
    if (!app) return res.send("Application not found").status(400)
    res.render("login.html", {
        ...app, state, client_id
    })
})


app.post('/oauth2/validate', (req, res) => {
    const { username, password, redirect_uri, state, client_id } = req.body

    pam.authenticate(username, password, function (error) {
        if (error) return res.send("Wrong credentials").status(401)
        else {
            const code = Math.random().toString(32).slice(2)
            console.log(global.tokens)
            global.tokens[code] = {
                username, client_id, email: `${username}@hackclub.app`
            }
            return res.redirect(`${redirect_uri}?${new URLSearchParams({
                state, code
            })}`)
        }
    });
})

app.post('/oauth2/token', (req, res) => {
    const { token, client_id, client_secret } = req.body
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

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})


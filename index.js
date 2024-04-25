const express = require('express')
const nunjucks = require("nunjucks")
const bodyParser = require('body-parser');
const config = require("./config.js")
const crypto = require("crypto");
const child = require("node:child_process");
const fs = require("node:fs")
const { QuickDB } = require("quick.db");
const db = new QuickDB();
const app = express()
const ln = express()
const port = 3000
const pam = require('authenticate-pam');

nunjucks.configure('views', {
    autoescape: true,
    express: app,
    noCache: true
});

app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.sendFile(`${__dirname}/views/index.html`)
})

ln.get('/authorize/:username', async (req, res) => {
    const { username } = req.params
    const authCode = crypto.randomUUID().replaceAll("-", "")
    db.set(`local.${authCode}`, username)
    res.send(`Your Oauth2 verification code is ${authCode}\n`)
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


app.post('/oauth2/validate', async (req, res) => {
    var { username, password, auth_code, redirect_uri, state, client_id, scope } = req.body
    if (!scope) scope = "openid profile"
    const scopes = scope.replaceAll("+", " ").split(" ")
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
    if (auth_code) {
        const username = await db.get(`local.${auth_code}`)
        console.log(username)
        if (!username) return res.send("Wrong credentials").status(401)
        const code = crypto.randomUUID().replaceAll("-", "")
        const id = child.execSync(`id -u "${username}"`).toString().replace("\n", "").toLowerCase()
        var groups = ["nest-users"]
        try {
            groups = child.execSync(`groups "${username}" 2>/dev/null`).toString().split(" : ")[1].split(" ").map(group => group.replace("\n", "").toLowerCase())
        } catch (e) {
        };
        var emaila
        if (scopes.includes("email")) {
            const email = child.execSync(`ldapsearch -H ${config.ldap.hostname} -b dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -D cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -w '${config.ldap.password}' -LLL -o ldif-wrap=no '(cn=david)' 'mail' | grep mail: | cut -d' ' -f2`).toString()
            emaila = email
        } else {
            emaila = `${username}@hackclub.app`
        }

        await db.set(`tokens.${code}`, {
            username, client_id, id, groups, email: emaila, expires: new Date(new Date().setMinutes(new Date().getMinutes() + 5)).toISOString()
        })
        return res.redirect(`${redirect_uri}?${new URLSearchParams({
            state, code
        })}`)
    } else
        pam.authenticate(username, password, async function (error) {
            if (error) return res.send("Wrong credentials").status(401)
            else {
                const code = crypto.randomUUID().replaceAll("-", "")
                const id = child.execSync(`id -u "${username}"`).toString().replace("\n", "").toLowerCase()
                var groups = ["nest-users"]
                try {
                    groups = child.execSync(`groups "${username}" 2>/dev/null`).toString().split(" : ")[1].split(" ").map(group => group.replace("\n", "").toLowerCase())
                } catch (e) {
                }
                var emaila
                if (scopes.includes("email")) {
                    const email = child.execSync(`ldapsearch -H ${config.ldap.hostname} -b dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -D cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -w '${config.ldap.password}' -LLL -o ldif-wrap=no '(cn=david)' 'mail' | grep mail: | cut -d' ' -f2`).toString()
                    emaila = email
                } else {
                    emaila = `${username}@hackclub.app`
                }

                await db.set(`tokens.${code}`, {
                    username, client_id, id, groups, email: emaila, expires: new Date(new Date().setMinutes(new Date().getMinutes() + 5)).toISOString()
                })
                return res.redirect(`${redirect_uri}?${new URLSearchParams({
                    state, code
                })}`)
            }
        });
})

app.post('/oauth2/token', async (req, res) => {
    const { client_id, client_secret } = req.body
    var token = ""
    if (req.body.token) token = req.body.token
    else if (req.body.code) token = req.body.code
    else return res.send("Token not found").status(400)

    console.log(req.body)
    const app = config.applications[client_id]
    if (!app) return res.send("Application not found").status(400)

    if (client_secret != app.clientSecret) return res.send("Incorrect client secret").status(401)

    if (!await db.has(`tokens.${token}`) || await db.get(`tokens.${token}`).client_id != client_id || new Date() > await db.get(`tokens.${token}`).expires) return res.send("Token not found").status(400)

    res.json({
        access_token: token,
        refresh_token: token,
        token_type: "Bearer",
        expires: 10
    })
})

app.get('/oauth2/profile', async (req, res) => {
    const auth = req.headers.authorization
    if (!auth.includes("Bearer ")) return res.send("Not bearer authorization.").status(400)
    const profile = await db.get(`tokens.${auth.replace("Bearer ", "")}`)
    if (!profile) return res.send("Token expired or non-existant").status(401)
    delete profile.client_id
    res.json(profile)
})

app.get('/.well-known/openid-configuration', (req, res) => {
    res.sendFile(`${__dirname}/openid.json`)
})

app.listen(process.env.PORT || port, () => {
    console.log(`Nest OAuth listening on port ${process.env.PORT || port}`)
})
if (fs.existsSync("./.localauth.socket")) fs.rmSync("./.localauth.socket")
ln.listen("./.localauth.socket", () => {
    console.log(`Local auth ready.`)
})
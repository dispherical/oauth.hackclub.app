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
const port = 3000
const pam = require('authenticate-pam');

const { Server: SSHServer } = require('ssh2');
const ldap = require('ldapjs');
const path = require('path');
const hostKeyPath = path.join(__dirname, 'host.key');
const sshServers = {}; 
function getRandomPort() {
  return Math.floor(Math.random() * (65535 - 30000) + 30000);
}

nunjucks.configure('views', {
  autoescape: true,
  express: app,
  noCache: true
});

app.use(bodyParser.urlencoded({ extended: true }));

app.get('/oauth2/ssh-status/:auth_code', async (req, res) => {
  const { auth_code } = req.params;
  const info = sshServers[auth_code];
  if (!info) return res.json({ verified: false });
  res.json({ verified: !!info.verified });
});

app.get('/', (req, res) => {
  res.sendFile(`${__dirname}/views/index.html`)
})

app.get('/oauth2/authorize', async (req, res, next) => {
  var { client_id, response_type, state, scope } = req.query
  var end
  if (!scope) scope = "openid profile"
  const scopes = scope.split(" ")
  if (!scopes.includes("profile")) scopes.push("profile")
  if (response_type && response_type !== "code") return res.send("Only the code response type is supported.").status(400)
  const appConfig = config.applications[client_id]
  scopes.forEach(scope => {
    if (!appConfig.scopes.includes(scope)) {
      res.send(`Scope not approved: ${scope}`)
      end = true
    }
  })
  if (end) return
  if (!appConfig) return res.send("Application not found").status(400)
  console.log(scopes)

  const authCode = crypto.randomUUID().replaceAll("-", "")
  const sshPort = getRandomPort();
  const sshServer = new SSHServer({
    hostKeys: [fs.readFileSync(hostKeyPath)],
  }, (client) => {
    client.on('authentication', async (ctx) => {
      if (!ctx?.key) return ctx.reject();
      const publicKey = `${ctx.key?.algo} ${ctx.key?.data?.toString('base64')}`;
      const ldapClient = ldap.createClient({
        url: 'ldaps://37.27.51.33',
        tlsOptions: {
          rejectUnauthorized: false,
          servername: 'identity.hackclub.app',
          minVersion: 'TLSv1.2',
          maxVersion: 'TLSv1.2'
        },
        connectTimeout: 10000
      });
      ldapClient.bind('cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app', config.ldap.password, (err) => {
        if (err) return ctx.reject();
        const searchOpts = {
          scope: 'sub',
          filter: `(sshPublicKey=${publicKey}*)`
        };
        ldapClient.search('ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app', searchOpts, (err, res) => {
          if (err) return ctx.reject();
          let found = false;
          let username = null;
          res.on('searchEntry', (entry) => {
            let userInfo = {};
            entry.attributes.forEach(attr => {
              userInfo[attr.type] = attr.values.length > 1 ? attr.values : attr.values[0];
            });
            username = userInfo.cn;
            found = true;
          });
          res.on('error', (err) => {
            ldapClient.unbind();
            ctx.reject();
          });
          res.on('end', () => {
            ldapClient.unbind();
            if (found) {
              sshServers[authCode].verified = true;
              sshServers[authCode].username = username;
              ctx.accept();
            } else {
              ctx.reject();
            }
          });
        });
      });
    });
    client.on('ready', () => {
      client.once('session', (accept) => {
        const session = accept();
        session.once('pty', (accept) => accept && accept());
        session.once('shell', (accept) => {
          const stream = accept();
          stream.write(`Authenticated. You should automatically redirect to your application.\n`);
          stream.write(`You may now close this window.\n`);
          stream.end();
          client.end();
        });
      });
    });
    client.on('error', (err) => {
      console.error('SSH client error:', err.message);
    });
    client.on('close', () => {
    });
  });
  sshServer.on('error', (err) => {
    console.error('SSH server error:', err.message);
  });
  sshServer.listen(sshPort, () => {
    sshServers[authCode] = { port: sshPort, server: sshServer, username: null, verified: false };
  });

  res.render("login.html", {
    ...appConfig, state, client_id, scopes, scope, auth_code: authCode, ssh_port: sshPort
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
    const sshInfo = sshServers[auth_code];
    if (!sshInfo || !sshInfo.verified) {
      return res.send("SSH verification not completed. Please connect via SSH as instructed.").status(401)
    }
    const username = sshInfo.username;
    const code = crypto.randomUUID().replaceAll("-", "")
    const id = child.execSync(`id -u "${username}"`).toString().replace("\n", "").toLowerCase()
    var groups = ["nest-users"]
    try {
      groups = child.execSync(`groups "${username}" 2>/dev/null`).toString().split(" : ")[1].split(" ").map(group => group.replace("\n", "").toLowerCase())
    } catch (e) { }
    var emaila
    if (scopes.includes("email")) {
      const email = child.execSync(`ldapsearch -H ${config.ldap.hostname} -b dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -D cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -w '${config.ldap.password}' -LLL -o ldif-wrap=no '(cn=${username})' 'mail' | grep mail: | cut -d' ' -f2`).toString()
      emaila = email
    } else {
      emaila = `${username}@hackclub.app`
    }

    await db.set(`tokens.${code}`, {
      username, client_id, id, groups, email: emaila, expires: new Date(new Date().setMinutes(new Date().getMinutes() + 5)).toISOString()
    })
    try {
      sshInfo.server.close();
      delete sshServers[auth_code];
    } catch (e) { }
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
          const email = child.execSync(`ldapsearch -H ${config.ldap.hostname} -b dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -D cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app -w '${config.ldap.password}' -LLL -o ldif-wrap=no '(cn=${username})' 'mail' | grep mail: | cut -d' ' -f2`).toString()
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
    expires_in: 10,
    scrope: "openid profile"
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

app.listen(process.env.PORT || config.port || port, () => {
  console.log(`Nest OAuth listening on port ${process.env.PORT || port}`)
})

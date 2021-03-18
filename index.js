// Define our dependencies
const dotenv         = require('dotenv-flow').config()
const express        = require('express')
const session        = require('express-session')
const passport       = require('passport')
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy
const request        = require('request')
const handlebars     = require('handlebars')
const bodyParser     = require('body-parser')
const https          = require('https')
const crypto         = require('crypto')
const axios          = require('axios')


// Define our constants, you will change these with your own
const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID
const TWITCH_SECRET    = process.env.TWITCH_SECRET
const SESSION_SECRET   = process.env.SESSION_SECRET
const CALLBACK_URL     = process.env.CALLBACK_URL
const NGROK_TUNNEL_URL = process.env.NGROK_TUNNEL_URL

// Initialize Express and middlewares
var app = express()
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf
    }
}))
app.use(session({secret: SESSION_SECRET, resave: false, saveUninitialized: false}))
app.use(express.static('public'))
app.use(passport.initialize())
app.use(passport.session())

// Override passport profile function to get user profile from Twitch API
OAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  var options = {
    url: 'https://api.twitch.tv/helix/users',
    method: 'GET',
    headers: {
      'Client-ID': TWITCH_CLIENT_ID,
      'Accept': 'application/vnd.twitchtv.v5+json',
      'Authorization': 'Bearer ' + accessToken
    }
  }

  request(options, function (error, response, body) {
    if (response && response.statusCode == 200) {
      done(null, JSON.parse(body))
    } else {
      done(JSON.parse(body))
    }
  })
}

passport.serializeUser(function(user, done) {
    done(null, user)
})

passport.deserializeUser(function(user, done) {
    done(null, user)
})

passport.use('twitch', new OAuth2Strategy({
    authorizationURL: 'https://id.twitch.tv/oauth2/authorize',
    tokenURL: 'https://id.twitch.tv/oauth2/token',
    clientID: TWITCH_CLIENT_ID,
    clientSecret: TWITCH_SECRET,
    callbackURL: CALLBACK_URL,
    state: true
  },
  function(accessToken, refreshToken, profile, done) {
    profile.accessToken = accessToken
    profile.refreshToken = refreshToken

    // Securely store user profile in your DB
    //User.findOrCreate(..., function(err, user) {
    //  done(err, user)
    //})

    done(null, profile)
  }
))

// Set route to start OAuth link, this is where you define scopes to request
app.get('/auth/twitch', passport.authenticate('twitch', { scope: 'user_read' }))

// Set route for OAuth redirect
app.get('/auth/twitch/callback', passport.authenticate('twitch', { successRedirect: '/', failureRedirect: '/' }))

// Define a simple template to safely generate HTML with values from user's profile
var template = handlebars.compile(`
<html><head><title>Twitch Auth Sample</title></head>
<table>
    <tr><th>Access Token</th><td>{{accessToken}}</td></tr>
    <tr><th>Refresh Token</th><td>{{refreshToken}}</td></tr>
    <tr><th>Display Name</th><td>{{data.0.display_name}}</td></tr>
    <tr><th>Bio</th><td>{{data.0.description}}</td></tr>
    <tr><th>Image</th><td><img src="{{data.0.profile_image_url}}" /></td></tr>
</table></html>`)

// If user has an authenticated session, display it, otherwise display link to authenticate
app.get('/', function (req, res) {
  if(req.session && req.session.passport && req.session.passport.user) {
    console.log(req.session.passport.user.data)
    res.send(template(req.session.passport.user))
    axios
      .post(NGROK_TUNNEL_URL + '/createWebhook/' + req.session.passport.user.data[0].id, {
        test: 'test'
      })
      .then(res => {
        console.log(`statusCode: ${res.statusCode}`)
        console.log(res)
      })
      .catch(error => {
        console.error(error)
      })
  } else {
    res.send('<html><head><title>Twitch Auth Sample</title></head><a href="/auth/twitch"><img src="http://ttv-api.s3.amazonaws.com/assets/connect_dark.png"></a></html>')
  }
})

app.post('/createWebhook/:broadcasterId', (req, res) => {
    var createWebHookParams = {
        host: "api.twitch.tv",
        path: "helix/eventsub/subscriptions",
        method: 'POST',
        headers: {
            "Content-Type": "application/json",
            "Client-ID": TWITCH_CLIENT_ID,
            "Authorization": "Bearer "+ TWITCH_SECRET
        }
    }
    var createWebHookBody = {
        "type": "channel.follow",
        "version": "1",
        "condition": {
            "broadcaster_user_id": req.params.broadcasterId
        },
        "transport": {
            "method": "webhook",
            // For testing purposes you can use an ngrok https tunnel as your callback URL
            "callback": NGROK_TUNNEL_URL+"/notification", // If you change the /notification path make sure to also adjust in line 69
            "secret": "keepItSecretKeepItSafe" // Replace with your own secret
        }
    }
    var responseData = ""
    var webhookReq = https.request(createWebHookParams, (result) => {
        result.setEncoding('utf8')
        result.on('data', function(d) {
                responseData = responseData + d
            })
            .on('end', function(result) {
                var responseBody = JSON.parse(responseData)
                res.send(responseBody)
            })
    })
    webhookReq.on('error', (e) => { console.log("Error") })
    webhookReq.write(JSON.stringify(createWebHookBody))
    webhookReq.end()
})

function verifySignature(messageSignature, messageID, messageTimestamp, body) {
    let message = messageID + messageTimestamp + body
    let signature = crypto.createHmac('sha256', "keepItSecretKeepItSafe").update(message) // Remember to use the same secret set at creation
    let expectedSignatureHeader = "sha256=" + signature.digest("hex")

    return expectedSignatureHeader === messageSignature
}

app.post('/notification', (req, res) => {
    if (!verifySignature(req.header("Twitch-Eventsub-Message-Signature"),
            req.header("Twitch-Eventsub-Message-Id"),
            req.header("Twitch-Eventsub-Message-Timestamp"),
            req.rawBody)) {
        res.status(403).send("Forbidden") // Reject requests with invalid signatures
    } else {
        if (req.header("Twitch-Eventsub-Message-Type") === "webhook_callback_verification") {
            console.log(req.body.challenge)
            res.send(req.body.challenge) // Returning a 200 status with the received challenge to complete webhook creation flow

        } else if (req.header("Twitch-Eventsub-Message-Type") === "notification") {
            console.log(req.body.event) // Implement your own use case with the event data at this block
            res.send("") // Default .send is a 200 status
        }
    }
})

app.listen(3000, function () {
  console.log('Twitch auth sample listening on port 3000!')
})

const express = require('express')
const path = require('path')
const https = require('https');
const fs = require('fs');
const helmet = require('helmet')
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config(); 

const app = express()
const port = 3000;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
    callbackURL:'/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

function verifyCallback(accessToken, refreshToken, profile, done){
    console.log('Google Profile', profile);
    done(null, profile);
}

passport.use( new Strategy(AUTH_OPTIONS, verifyCallback))

// saving session to the cookie
passport.serializeUser((user, done) =>{
    done(null, user.id)
})

// reading session from cookie
passport.deserializeUser((obj, done) =>{
    done(null, obj)
})


app.use(helmet());
app.use(cookieSession({
    name: 'session',
    maxAge: 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
}))


app.use(passport.initialize());
app.use(passport.session())

function checkLoggedIn(req, res, next){
    const isLoggedIn = req.isAuthenticated() && req.user;
    if(!isLoggedIn){
        return res.status(401).json({
            error:'You must logged in!'
        })
    }
    next();
}

app.get('/auth/google',passport.authenticate('google',{
        scope:['email']
    }) 
    ,(req, res) =>{
        console.log(' google signin')
    }
)

app.get('/auth/google/callback', passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true
    }), 
    (req, res)=>{
        console.log(' google called us back !!!')
    }
)

app.get('/failure', (req, res) =>{
    return res.send('Failed to log in');
})

app.get('/auth/logout', (req, res) =>{
    req.logOut();
    return res.status(302).redirect('/')
})

app.get('/secret',checkLoggedIn, (req,res)=>{
    return res.send('secret value is 42')
})

app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
)

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
}, app).listen(port, () => console.log(`Example app listening on port port!`))
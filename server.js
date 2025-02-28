const https = require('https');
const selfsigned = require('selfsigned');
const fs = require('fs');
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(session({ secret: process.env.JWT_SECRET, resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Configuration de la stratégie Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://localhost:3000/oauth2/redirect/google',
    scope: ['profile', 'email', 'openid'],
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Configuration de la stratégie Facebook
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: 'https://localhost:3000/oauth2/redirect/facebook',
    profileFields: ['id', 'emails', 'name'],
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Configuration de la stratégie GitHub
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'https://localhost:3000/oauth2/redirect/github',
    scope: ['profile', 'email', 'openid'],
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Sérialisation et désérialisation de l'utilisateur
passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((user, done) => {
    done(null, user);
});

// Lire les fichiers de certificat
const options = {
    key: fs.readFileSync('certs/localhost-key.pem'),
    cert: fs.readFileSync('certs/localhost.pem'),
};

// Si tu souhaites générer un certificat auto-signé (optionnel si tu veux en générer un à la volée)
const attrs = [{ name: 'commonName', value: 'localhost' }];
const cert = selfsigned.generate(attrs, options);

// Sauvegarder le certificat et la clé dans des fichiers (optionnel si tu utilises tes propres fichiers)
fs.writeFileSync('certs/server.crt', cert.cert);
fs.writeFileSync('certs/server.key', cert.private);

// Routes et autres configurations
app.get('/', (req, res) => {
    res.send('Hello, secure world!');
});

// Routes d'authentification OAuth
app.get('/login/federated/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/oauth2/redirect/google', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    const token = jwt.sign(req.user, process.env.JWT_SECRET);
    res.json({ message: 'Authentication successful with Google', token });
});

app.get('/login/federated/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/oauth2/redirect/facebook', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => {
    const token = jwt.sign(req.user, process.env.JWT_SECRET);
    res.json({ message: 'Authentication successful with Facebook', token });
});

app.get('/login/federated/github', passport.authenticate('github'));
app.get('/oauth2/redirect/github', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
    const token = jwt.sign(req.user, process.env.JWT_SECRET);
    res.json({ message: 'Authentication successful with Github', token });
});

// Route protégée (exemple)
app.get('/profile', (req, res) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to authenticate token' });
        }
        res.json(decoded);
    });
});

// Créer le serveur HTTPS
https.createServer(options, app).listen(3000, () => {
    console.log('Server is running on https://localhost:3000');
});

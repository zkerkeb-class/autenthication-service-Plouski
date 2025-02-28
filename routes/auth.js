const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

const generateTokens = (user) => {
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRATION });

    user.refreshToken = refreshToken;
    user.save();

    return { accessToken, refreshToken };
};

// Middleware pour protéger les routes
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });

        req.user = user;
        next();
    });
};

// OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), async (req, res) => {
    const tokens = generateTokens(req.user);
    res.json({ message: "Authentication successful with Google", tokens });
});

router.get('/facebook', passport.authenticate('facebook', { scope: ['email'] }));
router.get('/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), async (req, res) => {
    const tokens = generateTokens(req.user);
    res.json({ message: "Authentication successful with Facebook", tokens });
});

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/github/callback', passport.authenticate('github', { failureRedirect: '/' }), async (req, res) => {
    const tokens = generateTokens(req.user);
    res.json({ message: "Authentication successful with Github", tokens });
});

// Refresh Token
router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(403).json({ message: 'Refresh token required' });

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET); // vérifier le jeton
        const user = await User.findById(decoded.id);
        if (!user) return res.status(403).json({ message: 'User not found' });

        const tokens = generateTokens(user);
        res.json(tokens);
    } catch (error) {
        return res.status(401).json({ message: 'Invalid refresh token' });
    }
});

// Route protégée
router.get('/profile', authenticateJWT, async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json(user);
});

module.exports = router;
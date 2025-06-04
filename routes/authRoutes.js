const express = require('express');
const passport = require('passport');
const crypto = require('crypto');
const AuthController = require('../controllers/authController');
const logger = require('../utils/logger');

const router = express.Router();

// ───────────── Middleware de validation des providers ─────────────
const validateProvider = (req, res, next) => {
  const allowedProviders = ['google', 'facebook', 'github'];
  const provider = req.params.provider || req.path.split('/')[2];
  
  if (provider && !allowedProviders.includes(provider)) {
    logger.warn('❌ Provider OAuth non autorisé', { 
      provider, 
      ip: req.ip,
      allowedProviders 
    });
    
    return res.status(400).json({
      error: 'Provider non supporté',
      message: `Le provider '${provider}' n'est pas supporté`,
      supportedProviders: allowedProviders
    });
  }
  
  next();
};

// ───────────── Routes OAuth Google ─────────────
router.get('/oauth/google', 
  validateProvider,
  (req, res, next) => {
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state;
    
    logger.info('➡️ Initiation OAuth Google', { 
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      state: state.substring(0, 8) + '...'
    });
    
    next();
  }, 
  (req, res, next) => {
    passport.authenticate('google', {
      scope: [
        'openid',
        'profile', 
        'email'
      ],
      accessType: 'offline',
      prompt: 'consent',
      state: req.session.oauthState
    })(req, res, next);
  }
);

router.get('/oauth/google/callback',
  validateProvider,
  (req, res, next) => {
    const providedState = req.query.state;
    const expectedState = req.session.oauthState;
    
    logger.info('🔍 Validation state OAuth Google', {
      providedState: providedState?.substring(0, 8) + '...',
      expectedState: expectedState?.substring(0, 8) + '...',
      hasProvidedState: !!providedState,
      hasExpectedState: !!expectedState
    });
    
    if (!providedState || !expectedState || providedState !== expectedState) {
      logger.error('🚨 Validation CSRF échouée - Google OAuth', {
        ip: req.ip,
        hasProvidedState: !!providedState,
        hasExpectedState: !!expectedState,
        statesMatch: providedState === expectedState
      });
      
      delete req.session.oauthState;
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=csrf_failed&provider=google`);
    }
    
    delete req.session.oauthState;
    next();
  },
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=oauth_failed&provider=google`,
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

// ───────────── Routes OAuth Facebook ─────────────
router.get('/oauth/facebook',
  validateProvider,
  (req, res, next) => {
    logger.info('➡️ Initiation OAuth Facebook (mode développement)', { 
      ip: req.ip,
      sessionID: req.sessionID,
      environment: process.env.NODE_ENV || 'development'
    });
    
    if (process.env.NODE_ENV !== 'production') {
      req.session.facebookOAuthActive = true;
      req.session.save((err) => {
        if (err) {
          logger.error('❌ Erreur sauvegarde session:', err);
        }
        next();
      });
    } else {
      next();
    }
  },
  passport.authenticate('facebook', {
    scope: ['email', 'public_profile'],
    auth_type: 'rerequest'
  })
);

router.get('/oauth/facebook/callback',
  validateProvider,
  (req, res, next) => {
    if (process.env.NODE_ENV !== 'production') {
      logger.info('🔍 Facebook OAuth callback (mode développement)', {
        ip: req.ip,
        sessionID: req.sessionID,
        hasFacebookSession: !!req.session?.facebookOAuthActive,
        query: Object.keys(req.query)
      });
      
      delete req.session.facebookOAuthActive;
      
      next();
    } else {
      const hasValidSession = !!req.session?.oauthProvider;
      
      if (!hasValidSession) {
        logger.error('🚨 Session invalide - Facebook OAuth (production)', {
          ip: req.ip
        });
        
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=session_invalid&provider=facebook`);
      }
      
      delete req.session.oauthProvider;
      next();
    }
  },
  passport.authenticate('facebook', { 
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=oauth_failed&provider=facebook`,
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

// ───────────── Routes OAuth GitHub ─────────────
router.get('/oauth/github',
  validateProvider,
  (req, res, next) => {
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state;
    
    logger.info('➡️ Initiation OAuth GitHub', { 
      ip: req.ip,
      state: state.substring(0, 8) + '...'
    });
    
    next();
  },
  (req, res, next) => {
    passport.authenticate('github', {
      scope: ['user:email', 'read:user'],
      state: req.session.oauthState
    })(req, res, next);
  }
);

router.get('/oauth/github/callback',
  validateProvider,
  (req, res, next) => {
    const providedState = req.query.state;
    const expectedState = req.session.oauthState;
    
    if (!providedState || !expectedState || providedState !== expectedState) {
      logger.error('🚨 Validation CSRF échouée - GitHub OAuth', {
        ip: req.ip,
        hasProvidedState: !!providedState,
        hasExpectedState: !!expectedState
      });
      
      delete req.session.oauthState;
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=csrf_failed&provider=github`);
    }
    
    delete req.session.oauthState;
    next();
  },
  passport.authenticate('github', { 
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth?error=oauth_failed&provider=github`,
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

// ───────────── Route de déconnexion OAuth ─────────────
router.post('/oauth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      logger.error('❌ Erreur lors de la déconnexion', { error: err.message });
      return res.status(500).json({
        error: 'Erreur de déconnexion',
        message: 'Impossible de fermer la session'
      });
    }
    
    req.session.destroy((err) => {
      if (err) {
        logger.error('❌ Erreur destruction session', { error: err.message });
      }
      
      res.clearCookie('auth.session.id');
      
      logger.info('✅ Déconnexion OAuth réussie', { 
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      
      res.status(200).json({
        message: 'Déconnexion réussie',
        timestamp: new Date().toISOString()
      });
    });
  });
});

// ───────────── Route d'information sur les providers disponibles ─────────────
router.get('/oauth/providers', (req, res) => {
  const providers = {
    google: {
      name: 'Google',
      available: !!process.env.GOOGLE_CLIENT_ID,
      features: ['openid', 'profile', 'email'],
      authUrl: '/auth/oauth/google',
      testUrl: '/auth/oauth/test/google',
      security: 'CSRF with state parameter'
    },
    facebook: {
      name: 'Facebook',
      available: !!process.env.FACEBOOK_CLIENT_ID,
      features: ['profile', 'email'],
      authUrl: '/auth/oauth/facebook',
      testUrl: '/auth/oauth/test/facebook',
      security: process.env.NODE_ENV === 'production' ? 'Session-based validation' : 'Development mode (relaxed)'
    },
    github: {
      name: 'GitHub',
      available: !!process.env.GITHUB_CLIENT_ID,
      features: ['profile', 'email'],
      authUrl: '/auth/oauth/github',
      testUrl: '/auth/oauth/test/github',
      security: 'CSRF with state parameter'
    }
  };

  const availableProviders = Object.entries(providers)
    .filter(([provider]) => provider.available)
    .reduce((acc, [key, provider]) => {
      acc[key] = provider;
      return acc;
    }, {});

  res.json({
    supportedProviders: Object.keys(availableProviders),
    providers: availableProviders,
    security: {
      csrf: true,
      openIdConnect: true,
      httpsOnly: process.env.NODE_ENV === 'production'
    },
    environment: process.env.NODE_ENV || 'development',
    developmentMode: process.env.NODE_ENV !== 'production',
    endpoints: {
      test: process.env.NODE_ENV !== 'production' ? '/auth/oauth/test/:provider' : 'disabled',
      debug: process.env.NODE_ENV !== 'production' ? '/auth/debug/session' : 'disabled'
    }
  });
});

// ───────────── Route de validation des tokens ─────────────
router.get('/oauth/validate/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const JwtConfig = require('../config/jwtConfig');
    
    const decoded = JwtConfig.verifyToken(token);
    
    // Optionnel: vérifier que l'utilisateur existe encore
    const dataService = require('../services/dataService');
    let user = null;
    
    try {
      user = await dataService.findUserById(decoded.userId);
    } catch (error) {
      logger.debug('Erreur complète :', error);
      const User = require('../models/User');
      user = await User.findById(decoded.userId).select('-password');
    }
    
    if (!user) {
      return res.status(401).json({
        valid: false,
        error: 'Utilisateur non trouvé'
      });
    }
    
    res.json({
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      },
      tokenInfo: {
        issued: new Date(decoded.iat * 1000),
        expires: new Date(decoded.exp * 1000)
      }
    });
    
  } catch (error) {
    res.status(401).json({
      valid: false,
      error: error.message
    });
  }
});

module.exports = router;
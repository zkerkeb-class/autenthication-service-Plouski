const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const router = express.Router();

// Fonction pour générer les tokens
// Fonction corrigée pour générer les tokens
const generateTokens = (user) => {
  // Générer un jti (JWT ID) unique pour le token
  const jti = crypto.randomBytes(16).toString("hex");
  
  // Calculer correctement la date d'expiration
  const expiration = Math.floor(Date.now() / 1000) + 
    (parseInt(process.env.JWT_EXPIRATION.replace('m', '')) * 60); // Convertir minutes en secondes
  
  // Créer les claims standard pour OpenID Connect
  const payload = {
    iss: process.env.OIDC_ISSUER, // Issuer
    sub: user._id.toString(), // Subject (ID unique de l'utilisateur)
    aud: process.env.CLIENT_URL, // Audience
    exp: expiration, // Expiration correcte en timestamp Unix
    iat: Math.floor(Date.now() / 1000), // Issued At
    jti, // JWT ID unique
    // Claims utilisateur OpenID Connect
    name: user.name,
    email: user.email,
    picture: user.picture,
    provider: user.provider,
    roles: user.roles || ['user']
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET);
  
  // Refresh token avec moins de claims mais durée plus longue
  const refreshToken = jwt.sign({ 
    sub: user._id.toString(),
    jti: crypto.randomBytes(16).toString("hex"),
    exp: Math.floor(Date.now() / 1000) + 
      (parseInt(process.env.JWT_REFRESH_EXPIRATION.replace('d', '')) * 24 * 60 * 60) // Convertir jours en secondes
  }, process.env.JWT_SECRET);

  // Mettre à jour la date de dernière connexion
  user.lastLogin = new Date();
  user.refreshToken = refreshToken;
  user.save();

  return { 
    access_token: accessToken, 
    refresh_token: refreshToken,
    token_type: "Bearer",
    expires_in: parseInt(process.env.JWT_EXPIRATION.replace('m', '') * 60),
    id_token: accessToken // Dans OpenID Connect, l'id_token est retourné séparément
  };
};

// Middleware pour vérifier le token JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log("Auth header:", authHeader); // Log l'en-tête complet
  
  if (!authHeader) return res.status(401).json({ 
    error: "unauthorized",
    error_description: "Access token required" 
  });

  const token = authHeader.split(" ")[1];
  console.log("Token extrait:", token); // Log le token extrait
  
  if (!token) return res.status(401).json({ 
    error: "unauthorized",
    error_description: "Bearer token format required" 
  });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("Erreur de vérification:", err); // Log l'erreur spécifique
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          error: "invalid_token", 
          error_description: "Token expired" 
        });
      }
      return res.status(401).json({ 
        error: "invalid_token",
        error_description: "Invalid token" 
      });
    }

    console.log("Token valide, payload:", decoded); // Log le contenu du token
    req.user = decoded;
    next();
  });
};

// Middleware pour vérifier les rôles
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: "unauthorized",
        error_description: "Authentication required" 
      });
    }

    const userRoles = req.user.roles || ['user'];
    const hasRole = roles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      return res.status(403).json({ 
        error: "forbidden",
        error_description: "Insufficient permissions" 
      });
    }

    next();
  };
};

// OAuth Routes
router.get(
  "/google",
  passport.authenticate("google", { 
    scope: ["profile", "email"],
    // Ajout des paramètres OpenID Connect
    prompt: "select_account", // Force la sélection de compte Google
    access_type: "offline", // Nécessaire pour obtenir un refresh token
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/login-failed" }),
  async (req, res) => {
    try {
      const tokens = generateTokens(req.user);
      
      // Option 1: Rediriger vers le client avec les tokens en paramètres d'URL (moins sécurisé)
      // return res.redirect(`${process.env.CLIENT_URL}/auth/callback?access_token=${tokens.access_token}&refresh_token=${tokens.refresh_token}`);
      
      // Option 2: Rediriger vers le client avec un code temporaire (plus sécurisé)
      const authCode = crypto.randomBytes(32).toString('hex');
      // Stocker le code temporaire (normalement dans Redis ou autre cache)
      // tempAuthCodes.set(authCode, tokens, 5 * 60 * 1000); // 5 minutes d'expiration
      
      // Retourner directement les tokens (pour les tests)
      res.json({ 
        message: "Authentification réussie avec Google", 
        ...tokens
      });
    } catch (error) {
      console.error("Erreur d'authentification Google:", error);
      res.status(500).json({ 
        error: "server_error",
        error_description: "Une erreur est survenue lors de l'authentification" 
      });
    }
  }
);

router.get(
  "/facebook",
  passport.authenticate("facebook", { 
    scope: ["email"],
    // Paramètres supplémentaires pour Facebook
    auth_type: "rerequest"
  })
);

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/auth/login-failed" }),
  async (req, res) => {
    try {
      const tokens = generateTokens(req.user);
      res.json({ 
        message: "Authentification réussie avec Facebook", 
        ...tokens
      });
    } catch (error) {
      console.error("Erreur d'authentification Facebook:", error);
      res.status(500).json({ 
        error: "server_error",
        error_description: "Une erreur est survenue lors de l'authentification" 
      });
    }
  }
);

router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/auth/login-failed" }),
  async (req, res) => {
    try {
      const tokens = generateTokens(req.user);
      res.json({ 
        message: "Authentification réussie avec Github", 
        ...tokens
      });
    } catch (error) {
      console.error("Erreur d'authentification GitHub:", error);
      res.status(500).json({ 
        error: "server_error", 
        error_description: "Une erreur est survenue lors de l'authentification" 
      });
    }
  }
);

// Endpoint pour échec de connexion
router.get("/login-failed", (req, res) => {
  res.status(401).json({ 
    error: "login_failed",
    error_description: "L'authentification a échoué" 
  });
});

// Endpoint pour rafraîchir le token (conforme à OAuth 2.0)
router.post("/token", async (req, res) => {
  const { grant_type, refresh_token } = req.body;

  // Vérifier que c'est bien une demande de refresh token
  if (grant_type !== "refresh_token" || !refresh_token) {
    return res.status(400).json({ 
      error: "invalid_request",
      error_description: "Le grant_type doit être 'refresh_token' et un refresh_token doit être fourni" 
    });
  }

  try {
    const decoded = jwt.verify(refresh_token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.sub);
    
    if (!user || user.refreshToken !== refresh_token) {
      return res.status(401).json({ 
        error: "invalid_grant",
        error_description: "Refresh token invalide ou révoqué" 
      });
    }

    const tokens = generateTokens(user);
    res.json(tokens);
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: "invalid_grant", 
        error_description: "Refresh token expiré" 
      });
    }
    
    console.error("Erreur lors du rafraîchissement du token:", error);
    return res.status(401).json({ 
      error: "invalid_grant",
      error_description: "Refresh token invalide" 
    });
  }
});

// Endpoint pour révoquer un token (conforme à OAuth 2.0 RFC 7009)
router.post("/revoke", authenticateJWT, async (req, res) => {
  const { token, token_type_hint } = req.body;
  
  if (!token) {
    return res.status(400).json({ 
      error: "invalid_request",
      error_description: "Le paramètre 'token' est requis" 
    });
  }
  
  try {
    // Si c'est un refresh token
    if (token_type_hint === "refresh_token" || !token_type_hint) {
      const user = await User.findById(req.user.sub);
      if (user && user.refreshToken === token) {
        user.refreshToken = null;
        await user.save();
      }
    }
    
    // Par spécification, on renvoie toujours 200 même si le token n'existait pas
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Erreur lors de la révocation du token:", error);
    res.status(500).json({ 
      error: "server_error",
      error_description: "Une erreur est survenue" 
    });
  }
});

// Routes protégées
router.get("/userinfo", authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) {
      return res.status(404).json({ 
        error: "not_found",
        error_description: "Utilisateur non trouvé" 
      });
    }

    // Retourner le profil utilisateur conforme à OpenID Connect
    res.json(user.toOpenIDProfile());
  } catch (error) {
    console.error("Erreur lors de la récupération du profil:", error);
    res.status(500).json({ 
      error: "server_error",
      error_description: "Une erreur est survenue" 
    });
  }
});

// Route de déconnexion (conforme à OpenID Connect)
router.get("/logout", authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (user) {
      user.refreshToken = null;
      await user.save();
    }

    // Paramètres de déconnexion OpenID Connect
    const post_logout_redirect_uri = req.query.post_logout_redirect_uri || process.env.CLIENT_URL;
    
    res.json({ 
      success: true,
      message: "Déconnexion réussie", 
      redirect_uri: post_logout_redirect_uri 
    });
  } catch (error) {
    console.error("Erreur lors de la déconnexion:", error);
    res.status(500).json({ 
      error: "server_error",
      error_description: "Une erreur est survenue lors de la déconnexion" 
    });
  }
});

// Endpoint administratif (exemple de contrôle de rôle)
router.get("/admin", authenticateJWT, checkRole(['admin']), (req, res) => {
  res.json({ message: "Accès administrateur autorisé" });
});

// OpenID Connect Discovery endpoint
router.get("/.well-known/openid-configuration", (req, res) => {
  const baseUrl = process.env.API_URL || "https://localhost:3000";
  
  res.json({
    issuer: process.env.OIDC_ISSUER || baseUrl,
    authorization_endpoint: `${baseUrl}/auth/authorize`,
    token_endpoint: `${baseUrl}/auth/token`,
    userinfo_endpoint: `${baseUrl}/auth/userinfo`,
    jwks_uri: process.env.OIDC_JWKS_URI || `${baseUrl}/auth/.well-known/jwks.json`,
    registration_endpoint: `${baseUrl}/auth/register`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code", "id_token", "token id_token"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    claims_supported: [
      "iss", "sub", "aud", "exp", "iat", "auth_time",
      "name", "given_name", "family_name", "nickname", "picture", "email", "email_verified"
    ],
    revocation_endpoint: `${baseUrl}/auth/revoke`,
    end_session_endpoint: `${baseUrl}/auth/logout`,
  });
});

// JWKS endpoint pour la vérification des signatures de token
router.get("/.well-known/jwks.json", (req, res) => {
  // Normalement, vous utiliseriez une paire de clés RSA pour signer les tokens
  // Pour l'exemple, nous retournons une configuration vide
  res.json({
    keys: [
      // Ici, vous inséreriez les clés publiques pour vérifier les signatures
      // Exemple: { kty: "RSA", kid: "key-id-1", use: "sig", ... }
    ]
  });
});

module.exports = router;
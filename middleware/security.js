const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const logger = require("../utils/logger");

class SecurityMiddleware {
  // Rate limiting avancé par utilisateur
  static createAdvancedRateLimit() {
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: (req) => {
        if (req.user && req.user.role === "admin") {
          return 200;
        }
        if (req.user) {
          return 100;
        }
        return 50;
      },
      keyGenerator: (req) => {
        return req.user ? `user_${req.user.userId}` : `ip_${req.ip}`;
      },
      handler: (req, res) => {
        logger.warn("🛡️ Rate limit dépassé", {
          ip: req.ip,
          userId: req.user?.userId,
          userAgent: req.headers["user-agent"],
        });

        res.status(429).json({
          error: "Trop de requêtes",
          message: "Veuillez patienter avant de réessayer",
          retryAfter: Math.round(req.rateLimit.resetTime / 1000),
        });
      },
      standardHeaders: true,
      legacyHeaders: false,
    });
  }

  // Rate limiting spécifique pour OAuth
  static createOAuthRateLimit() {
    return rateLimit({
      windowMs: 5 * 60 * 1000,
      max: 10,
      keyGenerator: (req) => `oauth_${req.ip}`,
      handler: (req, res) => {
        logger.warn("🛡️ Rate limit OAuth dépassé", {
          ip: req.ip,
          provider: req.params.provider || "unknown",
        });

        res.status(429).json({
          error: "Trop de tentatives OAuth",
          message: "Veuillez patienter 5 minutes avant de réessayer",
        });
      },
    });
  }

  /**
   * Validation des certificats et signatures OAuth
   */
  static validateOAuthSecurity() {
    return async (req, res, next) => {
      if (req.path.includes("/oauth/callback")) {
        // Validation du state parameter pour prévenir CSRF
        const state = req.query.state;
        const expectedState = req.session?.oauthState;

        if (!state || state !== expectedState) {
          logger.error("🚨 Tentative CSRF détectée sur OAuth callback", {
            ip: req.ip,
            providedState: state,
            expectedState: expectedState,
          });

          return res.status(403).json({
            error: "Validation de sécurité échouée",
            message: "Tentative de falsification détectée",
          });
        }

        // Nettoyer le state après usage
        delete req.session.oauthState;
      }

      if (req.path.includes("/oauth/") && !req.path.includes("/callback")) {
        // Générer un state unique pour chaque tentative OAuth
        const state = crypto.randomBytes(32).toString("hex");
        req.session.oauthState = state;
        req.oauthState = state;
      }

      next();
    };
  }
}

module.exports = SecurityMiddleware;

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const logger = require("./utils/logger");
const PassportConfig = require("./config/passportConfig");
const SecurityMiddleware = require("./middleware/security");
const dataService = require("./services/dataService");
const authRoutes = require("./routes/authRoutes");
const metricsRoutes = require("./routes/metricsRoutes");
const {
  httpRequestDuration,
  serviceHealthStatus,
  externalServiceHealth,
} = require("./services/metricsServices");

const app = express();
const PORT = process.env.PORT || 5001;

console.log("🔥 Lancement du serveur d'authentification...");

(async () => {
  try {
    // ───────────── Vérification des services dépendants ─────────────
    logger.info("🔍 Vérification de la connexion au data-service...");
    try {
      await dataService.healthCheck();
      logger.info("✅ Data-service disponible");
    } catch (error) {
      logger.error("❌ Data-service indisponible:", error.message);
      logger.warn(
        "⚠️ Démarrage en mode dégradé - certaines fonctionnalités peuvent être limitées"
      );
    }

    // ───────────── Connexion MongoDB (fallback) ─────────────
    if (process.env.MONGODB_URI) {
      try {
        await mongoose.connect(process.env.MONGODB_URI);
        logger.info("✅ Connexion MongoDB établie (fallback)");
      } catch (error) {
        logger.warn("⚠️ MongoDB non disponible:", error.message);
      }
    }

    // ───────────── Middlewares de sécurité ─────────────
    app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
              "'self'",
              "'unsafe-inline'",
              "https://accounts.google.com",
              "https://connect.facebook.net",
            ],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: [
              "'self'",
              "https://accounts.google.com",
              "https://graph.facebook.com",
              "https://api.github.com",
            ],
            fontSrc: ["'self'", "https:", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
          },
        },
        crossOriginEmbedderPolicy: false,
      })
    );

    app.use(
      cors({
        origin: process.env.CORS_ORIGIN?.split(",") || [
          "http://localhost:3000",
        ],
        credentials: true,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
      })
    );

    // ───────────── Middlewares de parsing ─────────────
    app.use(
      express.json({
        limit: "1mb",
        verify: (req, res, buf) => {
          req.rawBody = buf;
        },
      })
    );

    app.use(express.urlencoded({ extended: true, limit: "1mb" }));

    // ───────────── Session avec sécurité renforcée ─────────────
    app.use(
      session({
        secret: process.env.SESSION_SECRET || "your-super-secret-session-key",
        resave: false,
        saveUninitialized: false,
        cookie: {
          secure: process.env.NODE_ENV === "production",
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000,
          sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
        },
        name: "auth.session.id",
      })
    );

    // ───────────── Middlewares de sécurité avancés ─────────────

    // Rate limiting général
    app.use(SecurityMiddleware.createAdvancedRateLimit());

    // ───────────── Middleware de monitoring temps de réponse ─────────────
    app.use((req, res, next) => {
      const start = process.hrtime();

      res.on("finish", () => {
        const duration = process.hrtime(start);
        const seconds = duration[0] + duration[1] / 1e9;

        // Mesurer le temps de réponse
        httpRequestDuration.observe(
          {
            method: req.method,
            route: req.path,
            status_code: res.statusCode,
          },
          seconds
        );
      });
      next();
    });

    // ───────────── Middleware de logging ─────────────
    app.use((req, res, next) => {
      const start = Date.now();
      res.on("finish", () => {
        const duration = Date.now() - start;
        logger.logHttpRequest(req, res, duration);
      });
      next();
    });

    // ───────────── Configuration Passport ─────────────
    app.use(passport.initialize());
    app.use(passport.session());
    PassportConfig.initializeStrategies();

    // ───────────── Routes avec sécurité OAuth ─────────────
    app.use("/auth/oauth", SecurityMiddleware.createOAuthRateLimit());
    app.use("/auth", SecurityMiddleware.validateOAuthSecurity());
    app.use("/auth", authRoutes);
    app.use("/metrics", metricsRoutes);

    // ───────────── Route de santé avec métriques ─────────────
    app.get("/health", async (req, res) => {
      const health = {
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        services: {},
      };

      try {
        await dataService.healthCheck();
        health.services.dataService = "healthy";
        externalServiceHealth.set({ service_name: "data-service" }, 1);
      } catch (error) {
        health.services.dataService = "unhealthy";
        health.status = "degraded";
        externalServiceHealth.set({ service_name: "data-service" }, 0);
      }

      if (mongoose.connection.readyState === 1) {
        health.services.mongodb = "healthy";
        externalServiceHealth.set({ service_name: "mongodb" }, 1);
      } else {
        health.services.mongodb = "unhealthy";
        health.status = "degraded";
        externalServiceHealth.set({ service_name: "mongodb" }, 0);
      }

      const isHealthy = health.status === "healthy" ? 1 : 0;
      serviceHealthStatus.set({ service_name: "auth-service" }, isHealthy);

      const statusCode = health.status === "healthy" ? 200 : 503;
      res.status(statusCode).json(health);
    });

    app.get("/ping", (req, res) =>
      res.status(200).json({
        status: "pong ✅",
        timestamp: new Date().toISOString(),
        service: "auth-service",
      })
    );

    // ───────────── Gestion 404 ─────────────
    app.use((req, res) => {
      logger.warn("📍 Route non trouvée", {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
      });

      res.status(404).json({
        error: "Route non trouvée",
        message: `La route ${req.method} ${req.path} n'existe pas`,
        availableRoutes: [
          "GET /health",
          "GET /ping",
          "GET /auth/oauth/google",
          "GET /auth/oauth/facebook",
          "GET /auth/oauth/github",
          "GET /metrics",
        ],
      });
    });

    // ───────────── Gestion erreurs globales ─────────────
    app.use((err, req, res) => {
      logger.logApiError(req, err);

      // Erreurs spécifiques OAuth
      if (err.name === "AuthenticationError") {
        return res.status(401).json({
          error: "Erreur d'authentification",
          message: "Échec de l'authentification OAuth",
          provider: req.params.provider || "unknown",
        });
      }

      // Erreurs de rate limiting
      if (err.status === 429) {
        return res.status(429).json({
          error: "Trop de requêtes",
          message: "Limite de taux dépassée, veuillez réessayer plus tard",
        });
      }

      // Erreurs de validation
      if (err.name === "ValidationError") {
        return res.status(400).json({
          error: "Erreur de validation",
          message: err.message,
          details: err.errors,
        });
      }

      // Erreurs de connexion au data-service
      if (err.message && err.message.includes("data-service")) {
        return res.status(503).json({
          error: "Service temporairement indisponible",
          message: "Le service de données est actuellement indisponible",
        });
      }

      const statusCode = err.statusCode || err.status || 500;
      const message =
        process.env.NODE_ENV === "production" && statusCode === 500
          ? "Erreur serveur interne"
          : err.message || "Une erreur est survenue";

      res.status(statusCode).json({
        error: "Erreur serveur",
        message,
        ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
      });
    });

    // ───────────── Démarrage du serveur ─────────────
    app.listen(PORT, () => {
      logger.info(
        `🚀 Serveur d'authentification en écoute sur http://localhost:${PORT}`
      );
      logger.info(`🔐 Environnement: ${process.env.NODE_ENV || "development"}`);
      logger.info(
        `🌐 CORS autorisé pour: ${
          process.env.CORS_ORIGIN || "http://localhost:3000"
        }`
      );
      logger.info(
        `📊 Métriques disponibles sur: http://localhost:${PORT}/metrics`
      );
      logger.info(
        `❤️ Health check disponible sur: http://localhost:${PORT}/health`
      );
    });
  } catch (err) {
    console.error("❌ Erreur fatale au démarrage :", err.message);
    console.error(err.stack);
    process.exit(1);
  }
})();

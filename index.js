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
const {
  register,
  httpRequestDuration,
  httpRequestsTotal,
  updateServiceHealth,
  updateActiveConnections,
  updateDatabaseHealth,
  updateExternalServiceHealth
} = require('./metrics');

const app = express();
const PORT = process.env.PORT || 5001;
const METRICS_PORT = process.env.METRICS_PORT || 9001;
const SERVICE_NAME = "auth-service";

console.log(`🔥 Lancement du ${SERVICE_NAME}...`);

// INITIALISATION ASYNC

(async () => {
  try {
    // Connexion MongoDB (optionnelle pour auth-service)
    if (process.env.MONGODB_URI) {
      try {
        await mongoose.connect(process.env.MONGODB_URI);
        logger.info("✅ Connexion MongoDB établie");
        updateDatabaseHealth('mongodb', true);
      } catch (error) {
        logger.warn("⚠️ MongoDB non disponible:", error.message);
        updateDatabaseHealth('mongodb', false);
      }
    }

    // Vérification data-service
    logger.info("🔍 Vérification de la connexion au data-service...");
    try {
      await dataService.healthCheck();
      logger.info("✅ Data-service disponible");
      updateExternalServiceHealth('data-service', true);
    } catch (error) {
      logger.error("❌ Data-service indisponible:", error.message);
      logger.warn("⚠️ Démarrage en mode dégradé");
      updateExternalServiceHealth('data-service', false);
    }

    // MIDDLEWARES DE SÉCURITÉ

    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com"],
          connectSrc: ["'self'", "https://accounts.google.com", "https://api.github.com"],
        },
      },
      crossOriginEmbedderPolicy: false,
    }));

    app.use(cors({
      origin: process.env.CORS_ORIGIN?.split(",") || ["http://localhost:3000"],
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    }));

    app.use(express.json({ limit: "1mb" }));
    app.use(express.urlencoded({ extended: true, limit: "1mb" }));

    // Session
    app.use(session({
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
    }));

    // Rate limiting spécifique
    app.use(SecurityMiddleware.createAdvancedRateLimit());

    // MIDDLEWARE DE MÉTRIQUES STANDARDISÉ

    let currentConnections = 0;

    app.use((req, res, next) => {
      const start = Date.now();
      currentConnections++;
      updateActiveConnections(currentConnections);

      res.on("finish", () => {
        const duration = (Date.now() - start) / 1000;
        currentConnections--;
        updateActiveConnections(currentConnections);

        httpRequestDuration.observe(
          {
            method: req.method,
            route: req.route?.path || req.path,
            status_code: res.statusCode,
          },
          duration
        );

        httpRequestsTotal.inc({
          method: req.method,
          route: req.route?.path || req.path,
          status_code: res.statusCode,
        });

        logger.info(`${req.method} ${req.path} - ${res.statusCode} - ${Math.round(duration * 1000)}ms`);
      });

      next();
    });

    // CONFIGURATION PASSPORT

    app.use(passport.initialize());
    app.use(passport.session());
    PassportConfig.initializeStrategies();

    // ROUTES SPÉCIFIQUES AUTH

    app.use("/auth/oauth", SecurityMiddleware.createOAuthRateLimit());
    app.use("/auth", SecurityMiddleware.validateOAuthSecurity());
    app.use("/auth", authRoutes);

    // ROUTES STANDARD

    // Métriques Prometheus
    app.get("/metrics", async (req, res) => {
      res.set("Content-Type", register.contentType);
      res.end(await register.metrics());
    });

    // Health check enrichi pour auth-service
    app.get("/health", async (req, res) => {
      const health = {
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        service: SERVICE_NAME,
        version: "1.0.0",
        dependencies: {}
      };

      try {
        await dataService.healthCheck();
        health.dependencies.dataService = "healthy";
        updateExternalServiceHealth('data-service', true);
      } catch (error) {
        health.dependencies.dataService = "unhealthy";
        health.status = "degraded";
        updateExternalServiceHealth('data-service', false);
      }

      if (mongoose.connection.readyState === 1) {
        health.dependencies.mongodb = "healthy";
        updateDatabaseHealth('mongodb', true);
      } else {
        health.dependencies.mongodb = "unhealthy";
        health.status = "degraded";
        updateDatabaseHealth('mongodb', false);
      }

      const isHealthy = health.status === "healthy";
      updateServiceHealth(SERVICE_NAME, isHealthy);

      const statusCode = isHealthy ? 200 : 503;
      res.status(statusCode).json(health);
    });

    // Vitals
    app.get("/vitals", (req, res) => {
      const activeSessions = req.sessionStore ? Object.keys(req.sessionStore.sessions || {}).length : 0;

      const vitals = {
        service: SERVICE_NAME,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        status: "running",
        active_connections: currentConnections,
        
        auth: {
          active_sessions: activeSessions,
          providers_enabled: {
            google: !!process.env.GOOGLE_CLIENT_ID,
            facebook: !!process.env.FACEBOOK_CLIENT_ID,
            github: !!process.env.GITHUB_CLIENT_ID
          },
          mongodb_connected: mongoose.connection.readyState === 1,
          data_service_available: false
        }
      };

      res.json(vitals);
    });

    // Ping
    app.get("/ping", (req, res) => {
      res.json({
        status: "pong ✅",
        service: SERVICE_NAME,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    });

    // GESTION D'ERREURS

    app.use((req, res) => {
      res.status(404).json({
        error: "Route non trouvée",
        service: SERVICE_NAME,
        message: `${req.method} ${req.path} n'existe pas`,
        availableRoutes: [
          "GET /health", "GET /vitals", "GET /metrics", "GET /ping",
          "GET /auth/oauth/google", "GET /auth/oauth/facebook", "GET /auth/oauth/github"
        ],
      });
    });

    app.use((err, req, res, next) => {
      logger.error(`💥 Erreur ${SERVICE_NAME}:`, err.message);

      if (err.name === "AuthenticationError") {
        return res.status(401).json({
          error: "Erreur d'authentification",
          service: SERVICE_NAME,
          message: "Échec de l'authentification OAuth",
        });
      }

      if (err.status === 429) {
        return res.status(429).json({
          error: "Trop de requêtes",
          service: SERVICE_NAME,
          message: "Limite de taux dépassée",
        });
      }

      res.status(err.statusCode || 500).json({
        error: "Erreur serveur",
        service: SERVICE_NAME,
        message: err.message || "Une erreur est survenue",
      });
    });

    // DÉMARRAGE

    // Serveur principal
    app.listen(PORT, () => {
      console.log(`🔐 ${SERVICE_NAME} démarré sur le port ${PORT}`);
      console.log(`📊 Métriques: http://localhost:${PORT}/metrics`);
      console.log(`❤️ Health: http://localhost:${PORT}/health`);
      console.log(`📈 Vitals: http://localhost:${PORT}/vitals`);
      console.log(`🔑 OAuth Google: http://localhost:${PORT}/auth/oauth/google`);
      
      updateServiceHealth(SERVICE_NAME, true);
      logger.info(`✅ ${SERVICE_NAME} avec métriques démarré`);
      
      if (mongoose.connection.readyState === 1) {
        logger.info("✅ MongoDB connecté - OAuth fonctionnel");
      } else {
        logger.warn("⚠️ MongoDB non connecté - OAuth peut ne pas fonctionner");
      }
    });

    // Serveur métriques séparé
    const metricsApp = express();
    metricsApp.get('/metrics', async (req, res) => {
      res.set('Content-Type', register.contentType);
      res.end(await register.metrics());
    });

    metricsApp.get('/health', (req, res) => {
      res.json({ status: 'healthy', service: `${SERVICE_NAME}-metrics` });
    });

    metricsApp.listen(METRICS_PORT, () => {
      console.log(`📊 Metrics server running on port ${METRICS_PORT}`);
    });

  } catch (err) {
    console.error("❌ Erreur fatale au démarrage :", err.message);
    updateServiceHealth(SERVICE_NAME, false);
    process.exit(1);
  }
})();

// GRACEFUL SHUTDOWN

function gracefulShutdown(signal) {
  console.log(`🔄 Arrêt ${SERVICE_NAME} (${signal})...`);
  updateServiceHealth(SERVICE_NAME, false);
  updateDatabaseHealth('mongodb', false);
  updateExternalServiceHealth('data-service', false);
  updateActiveConnections(0);
  
  setTimeout(() => {
    process.exit(0);
  }, 1000);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', reason);
  updateServiceHealth(SERVICE_NAME, false);
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  updateServiceHealth(SERVICE_NAME, false);
  process.exit(1);
});

module.exports = app;
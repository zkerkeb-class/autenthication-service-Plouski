const https = require("https");
const fs = require("fs");
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const dotenv = require("dotenv");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const helmet = require("helmet"); // Ajoutez cette dépendance pour la sécurité
const morgan = require("morgan"); // Ajoutez cette dépendance pour le logging
const rateLimit = require("express-rate-limit"); // Ajoutez cette dépendance pour limiter les requêtes

// Chargement des variables d'environnement avant tout
dotenv.config();

// Initialisation de l'application Express
const app = express();

// Chargement de la configuration Passport
require("./config/passport");

// Connexion à MongoDB avec gestion d'erreur
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true, 
    useUnifiedTopology: true
  })
  .then(() => console.log("✅ MongoDB connecté"))
  .catch((err) => {
    console.error("❌ Erreur de connexion à MongoDB:", err);
    process.exit(1);
  });

// Middlewares de sécurité et utilitaires
app.use(helmet()); // Sécurisation des en-têtes HTTP
app.use(morgan("dev")); // Logging des requêtes en développement

// Middleware de rate limiting pour prévenir les attaques par force brute
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limite à 100 requêtes par fenêtre
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "too_many_requests",
    error_description: "Trop de requêtes, veuillez réessayer plus tard"
  }
});
app.use("/auth/", apiLimiter); // Applique le rate limiting aux routes d'authentification

// Middleware pour parser le JSON et les cookies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuration CORS sécurisée
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// Configuration des sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // En production, utiliser cookies sécurisés
      httpOnly: true, // empêche l'accès aux cookies via JavaScript
      sameSite: "Strict", // empêche les attaques CSRF
      maxAge: 24 * 60 * 60 * 1000, // expiration après 24 heures
    },
  })
);

// Initialisation de Passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware pour exposer les informations de l'utilisateur connecté à l'application
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

// Routes de base
app.get("/", (req, res) => {
  res.json({
    message: "Service d'authentification OAuth2 et OpenID Connect",
    documentation: "/api-docs",
    version: "1.0.0"
  });
});

// Routes API
const authRoutes = require("./routes/auth");
app.use("/auth", authRoutes);

// Page de documentation API (optionnelle, à implémenter avec Swagger/OpenAPI)
app.get("/api-docs", (req, res) => {
  res.json({
    message: "Documentation de l'API",
    endpoints: {
      oauth: {
        google: "/auth/google",
        facebook: "/auth/facebook",
        github: "/auth/github"
      },
      tokens: "/auth/token",
      userinfo: "/auth/userinfo",
      logout: "/auth/logout"
    }
  });
});

// Middleware de gestion d'erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "server_error",
    error_description: "Une erreur serveur s'est produite"
  });
});

// Middleware pour les routes non trouvées
app.use((req, res) => {
  res.status(404).json({
    error: "not_found",
    error_description: "Ressource non trouvée"
  });
});

// Configuration du serveur HTTPS
let httpsOptions;
try {
  httpsOptions = {
    key: fs.readFileSync(path.join(__dirname, "certs/localhost-key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "certs/localhost.pem")),
  };
} catch (error) {
  console.warn("⚠️ Certificats SSL non trouvés. Le serveur va essayer de générer des certificats auto-signés.");
  
  // Génération de certificats auto-signés si nécessaires
  try {
    // Création du dossier certs s'il n'existe pas
    if (!fs.existsSync(path.join(__dirname, "certs"))) {
      fs.mkdirSync(path.join(__dirname, "certs"));
    }
    
    const selfsigned = require("selfsigned");
    const attrs = [{ name: "commonName", value: "localhost" }];
    const pems = selfsigned.generate(attrs, { days: 365 });
    
    fs.writeFileSync(path.join(__dirname, "certs/localhost-key.pem"), pems.private);
    fs.writeFileSync(path.join(__dirname, "certs/localhost.pem"), pems.cert);
    
    httpsOptions = {
      key: pems.private,
      cert: pems.cert
    };
    
    console.log("✅ Certificats auto-signés générés avec succès");
  } catch (certError) {
    console.error("❌ Impossible de générer des certificats:", certError);
    process.exit(1);
  }
}

// Démarrage du serveur HTTPS
const PORT = process.env.PORT || 3000;
const server = https.createServer(httpsOptions, app);

server.listen(PORT, () => {
  console.log(`✅ Serveur d'authentification démarré sur https://localhost:${PORT}`);
  console.log(`🔐 Mode: ${process.env.NODE_ENV || 'development'}`);
});
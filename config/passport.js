const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const User = require("../models/User");

require("dotenv").config();

/**
 * Fonction commune pour traiter les callbacks OAuth
 * Cette fonction recherche ou crée un utilisateur basé sur le profil OAuth
 */
const oauthCallback = async (accessToken, refreshToken, profile, done) => {
  try {
    console.log(`Profil OAuth reçu de ${profile.provider}:`, profile);

    // Détermination de l'email selon le provider
    let email = null;
    if (profile.emails && Array.isArray(profile.emails) && profile.emails.length > 0) {
      // Chercher d'abord un email vérifié, sinon prendre le premier
      email = profile.emails.find(e => e.verified)?.value || profile.emails[0]?.value;
    }
    
    // Email de fallback si aucun n'est disponible
    if (!email) {
      email = `${profile.id}@${profile.provider}.com`;
      console.log(`Aucun email trouvé, utilisation d'un email généré: ${email}`);
    }

    // Recherche de l'utilisateur existant
    let user = await User.findOne({
      provider: profile.provider,
      providerId: profile.id,
    });

    if (!user) {
      console.log("Utilisateur non trouvé, création d'un nouvel utilisateur...");
      
      // Extraction des informations du profil selon le provider
      const userData = {
        provider: profile.provider,
        providerId: profile.id,
        email: email,
        emailVerified: profile.emails?.[0]?.verified || false,
        name: profile.displayName || '',
        picture: profile.photos?.[0]?.value || null,
        // Informations supplémentaires pour OpenID Connect
        sub: `${profile.provider}|${profile.id}`, // Subject identifier unique
        locale: profile._json?.locale || null,
      };
      
      // Ajout des noms pour OpenID Connect si disponibles
      if (profile.name) {
        userData.givenName = profile.name.givenName || '';
        userData.familyName = profile.name.familyName || '';
      }
      
      user = await User.create(userData);
      console.log("Utilisateur créé:", user);
    } else {
      console.log("Utilisateur existant trouvé:", user._id);
      
      // Mise à jour des informations utilisateur si elles ont changé
      const updates = {};
      if (profile.photos?.[0]?.value && profile.photos[0].value !== user.picture) {
        updates.picture = profile.photos[0].value;
      }
      if (profile.displayName && profile.displayName !== user.name) {
        updates.name = profile.displayName;
      }
      
      // Si des mises à jour sont nécessaires
      if (Object.keys(updates).length > 0) {
        console.log("Mise à jour des informations utilisateur:", updates);
        Object.assign(user, updates);
        await user.save();
      }
    }

    return done(null, user);
  } catch (error) {
    console.error("Erreur dans oauthCallback:", error);
    return done(error, null);
  }
};

// Configuration Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
      // Paramètres OpenID Connect supplémentaires
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    oauthCallback
  )
);

// Configuration Facebook OAuth
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "emails", "name", "picture.type(large)"],
      enableProof: true // Améliore la sécurité des échanges avec Facebook
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("Profil Facebook:", profile);

      // Adaptation du profil Facebook pour correspondre au format attendu
      const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
      const adaptedProfile = { 
        ...profile, 
        emails: [{ value: email }],
        // Facebook ne fournit pas directement ces champs
        _json: {
          ...profile._json,
          locale: profile._json?.locale || 'fr_FR' // Par défaut
        }
      };

      return oauthCallback(accessToken, refreshToken, adaptedProfile, done);
    }
  )
);

// Configuration GitHub OAuth
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback",
      scope: ["user", "user:email"] // 'user:email' permet d'accéder aux emails privés
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("Profil GitHub:", profile);

      // GitHub nécessite parfois une requête supplémentaire pour obtenir les emails
      let email = null;
      if (profile.emails && Array.isArray(profile.emails)) {
        // Chercher d'abord un email primaire et vérifié
        email = profile.emails.find(e => e.primary && e.verified)?.value || 
                profile.emails[0]?.value;
      }
      email = email || `${profile.id}@github.com`;

      // Adaptation du profil GitHub
      const adaptedProfile = {
        ...profile,
        emails: [{ value: email, verified: true }],
        _json: {
          ...profile._json,
          locale: 'en' // GitHub ne fournit pas cette information
        }
      };

      return oauthCallback(accessToken, refreshToken, adaptedProfile, done);
    }
  )
);

// Sérialisation et désérialisation d'utilisateur pour les sessions
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    console.error("Erreur de désérialisation:", error);
    done(error, null);
  }
});

module.exports = {
  // Exporter les fonctions pour les tests et la réutilisation
  oauthCallback
};
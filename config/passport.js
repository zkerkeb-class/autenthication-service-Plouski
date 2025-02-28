const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const User = require("../models/User");

require("dotenv").config();

const oauthCallback = async (accessToken, refreshToken, profile, done) => {
  try {
    console.log("Profil OAuth reçu:", profile);

    let email =
      profile.emails?.[0]?.value || `${profile.id}@${profile.provider}.com`;
    console.log("Email généré:", email);

    let user = await User.findOne({
      providerId: profile.id,
      provider: profile.provider,
    });

    if (!user) {
      console.log(
        "Utilisateur non trouvé, création d'un nouvel utilisateur..."
      );
      user = await User.create({
        provider: profile.provider,
        providerId: profile.id,
        email: email,
        name:
          profile.displayName ||
          `${profile.name?.givenName || ""} ${profile.name?.familyName || ""}`.trim(),
        picture: profile.photos?.[0]?.value || null,
      });
      console.log("Utilisateur créé:", user);
    }

    return done(null, user);
  } catch (error) {
    console.error("Erreur dans oauthCallback:", error);
    return done(error, null);
  }
};

// Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    oauthCallback
  )
);

// Facebook OAuth
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "emails", "name", "picture.type(large)"],
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("Profil Facebook:", profile);

      const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;

      return oauthCallback(
        accessToken,
        refreshToken,
        { ...profile, emails: [{ value: email }] },
        done
      );
    }
  )
);

// GitHub OAuth
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback",
      scope: ["user:email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("Profil GitHub:", profile);

      let email = null;
      if (profile.emails && Array.isArray(profile.emails)) {
        email =
          profile.emails.find((e) => e.primary && e.verified)?.value ||
          profile.emails[0]?.value;
      }
      email = email || `${profile.id}@github.com`;

      return oauthCallback(
        accessToken,
        refreshToken,
        { ...profile, emails: [{ value: email }] },
        done
      );
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

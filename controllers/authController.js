const logger = require("../utils/logger");

class AuthController {
  
  // Méthode pour gérer les connexions OAuth
  static async handleOAuthSuccess(req, res, next) {
    try {
      if (!req.user) {
        return res
          .status(401)
          .json({ message: "Authentification OAuth échouée" });
      }

      const { user, accessToken, refreshToken } = req.user;
      const { _id, email, firstName, lastName, role, avatar } = user;

      logger.logAuthEvent("oauth_login", {
        userId: _id,
        provider: user.oauth?.provider,
      });

      const isApiClient = req.get("Accept") === "application/json";

      if (isApiClient) {
        return res.status(200).json({
          message: "Authentification OAuth réussie",
          user: {
            id: _id,
            email,
            firstName,
            lastName,
            role,
            avatar,
          },
          tokens: {
            accessToken,
            refreshToken,
          },
        });
      }

      const redirectUrl = new URL(
        process.env.FRONTEND_URL || "http://localhost:30005"
      );
      redirectUrl.pathname = "/oauth-callback";
      redirectUrl.searchParams.set("token", accessToken);

      return res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error(
        "Erreur lors du traitement de l'authentification OAuth",
        error
      );
      next(error);
    }
  }
}

module.exports = AuthController;

const axios = require("axios");
const logger = require("../utils/logger");

class DataService {
  constructor() {
    // Configuration avec variables multiples pour Docker
    const rawBaseURL = process.env.DATA_SERVICE_URL_DOCKER || 
                      process.env.DATA_SERVICE_URL || 
                      "http://localhost:5002";
    
    console.log(`🔗 Auth service using DATA_SERVICE_URL: ${rawBaseURL}`);
    
    this.baseURL = `${rawBaseURL}/api`;
    this.healthURL = `${rawBaseURL}/health`; // URL séparée pour health check

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 5000,
      headers: {
        "Content-Type": "application/json",
        "X-Service": "auth-service",
      },
    });

    // Client séparé pour health check
    this.healthClient = axios.create({
      baseURL: rawBaseURL,
      timeout: 3000,
      headers: {
        "Content-Type": "application/json",
        "X-Service": "auth-service",
      },
    });

    this.client.interceptors.request.use(
      (config) => {
        logger.info(
          `📡 Requête vers data-service: ${config.method?.toUpperCase()} ${
            config.url
          }`
        );
        return config;
      },
      (error) => {
        logger.error("❌ Erreur requête data-service:", error);
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        logger.info(
          `✅ Réponse data-service: ${response.status} ${response.config.url}`
        );
        return response;
      },
      (error) => {
        logger.error(
          `❌ Erreur réponse data-service: ${error.response?.status} ${error.config?.url}`,
          {
            message: error.response?.data?.message || error.message,
            status: error.response?.status,
          }
        );
        return Promise.reject(error);
      }
    );
  }

  // Créer un nouvel utilisateur
  async createUser(userData) {
    try {
      const response = await this.client.post("/users", {
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        password: userData.password,
        phoneNumber: userData.phoneNumber,
        role: userData.role || "user",
        isVerified: userData.isVerified || false,
        oauth: userData.oauth,
        createdAt: new Date(),
      });

      logger.info("👤 Utilisateur créé via data-service", {
        userId: response.data.id,
      });
      return response.data;
    } catch (error) {
      logger.error(
        "❌ Erreur création utilisateur:",
        error.response?.data || error.message
      );
      throw new Error(
        `Erreur création utilisateur: ${
          error.response?.data?.message || error.message
        }`
      );
    }
  }

  // Trouver un utilisateur par email
  async findUserByEmail(email) {
    try {
      const response = await this.client.get(
        `/users/email/${encodeURIComponent(email)}`
      );
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        return null;
      }
      logger.error(
        "❌ Erreur recherche utilisateur par email:",
        error.response?.data || error.message
      );
      throw new Error(
        `Erreur recherche utilisateur: ${
          error.response?.data?.message || error.message
        }`
      );
    }
  }

  // Trouver un utilisateur par ID
  async findUserById(userId) {
    try {
      const response = await this.client.get(`/users/${userId}`);
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        return null;
      }
      logger.error(
        "❌ Erreur recherche utilisateur par ID:",
        error.response?.data || error.message
      );
      throw new Error(
        `Erreur recherche utilisateur: ${
          error.response?.data?.message || error.message
        }`
      );
    }
  }

  // Mettre à jour un utilisateur
  async updateUser(userId, updateData) {
    try {
      const response = await this.client.put(`/users/${userId}`, updateData);
      logger.info("📝 Utilisateur mis à jour via data-service", { userId });
      return response.data;
    } catch (error) {
      logger.error(
        "❌ Erreur mise à jour utilisateur:",
        error.response?.data || error.message
      );
      throw new Error(
        `Erreur mise à jour utilisateur: ${
          error.response?.data?.message || error.message
        }`
      );
    }
  }

  // ✅ Health check corrigé - utilise /health directement
  async healthCheck() {
    try {
      const response = await this.healthClient.get("/health");
      return response.data;
    } catch (error) {
      logger.error("❌ Data-service non disponible:", error.message);
      throw new Error("Data-service non disponible");
    }
  }

  // Enregistrer un événement d'authentification
  async logAuthEvent(eventData) {
    try {
      await this.client.post("/auth-events", {
        ...eventData,
        timestamp: new Date(),
        service: "auth-service",
      });
    } catch (error) {
      logger.warn(
        "⚠️ Impossible d'enregistrer l'événement auth:",
        error.message
      );
    }
  }
}

const dataService = new DataService();

module.exports = dataService;
const winston = require('winston');
const { format, createLogger, transports } = winston;
const { combine, timestamp, printf, colorize, json } = format;

// Format personnalisé pour les logs console
const consoleFormat = printf(({ level, message, timestamp, ...meta }) => {
  return `${timestamp} [${level}]: ${message} ${
    Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
  }`;
});

// Créer le logger
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp(),
    json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
  exceptionHandlers: [
    new transports.File({ filename: 'logs/exceptions.log' })
  ],
  exitOnError: false
});

// Ajouter la sortie console en environnement de développement
if (process.env.NODE_ENV !== 'production') {
  logger.add(new transports.Console({
    format: combine(
      colorize(),
      timestamp(),
      consoleFormat
    )
  }));
}

// Fonction pour journaliser les événements d'authentification
logger.logAuthEvent = (event, metadata = {}) => {
  logger.info(`Auth event: ${event}`, {
    auth_event: event,
    ...metadata,
    timestamp: new Date().toISOString()
  });
};

// Fonction pour journaliser les requêtes HTTP
logger.logHttpRequest = (req, res, responseTime) => {
  logger.info('HTTP Request', {
    method: req.method,
    url: req.url,
    status: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.headers['user-agent'],
    userId: req.user?.userId || 'anonymous',
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });
};

// Fonction pour journaliser les erreurs d'API
logger.logApiError = (req, error) => {
  logger.error('API Error', {
    method: req.method,
    url: req.url,
    userId: req.user?.userId || 'anonymous',
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
    error: {
      message: error.message,
      stack: error.stack
    }
  });
};

module.exports = logger;
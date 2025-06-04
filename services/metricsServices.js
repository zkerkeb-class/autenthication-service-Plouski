const client = require('prom-client');

// Configuration de base
const register = new client.Registry();
client.collectDefaultMetrics({ register });

// Métriques temps de réponse HTTP
const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Temps de réponse des requêtes HTTP',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5],
  registers: [register],
});

// Métriques état de santé du service
const serviceHealthStatus = new client.Gauge({
  name: 'service_health_status',
  help: 'État de santé du service (1=healthy, 0=unhealthy)',
  labelNames: ['service_name'],
  registers: [register],
});

// Métriques disponibilité des services externes
const externalServiceHealth = new client.Gauge({
  name: 'external_service_health',
  help: 'État de santé des services externes (1=up, 0=down)',
  labelNames: ['service_name'],
  registers: [register],
});

module.exports = {
  register,
  httpRequestDuration,
  serviceHealthStatus,
  externalServiceHealth,
};
export const EnvConfiguration = () => ({
  environment: process.env.NODE_ENV || 'develop',
  mongodb: process.env.MONGO_DB || '',
  appPort: process.env.APP_PORT || 4001,
  jwtSecret: process.env.JWT_SECRET,
  oauthIssuer: process.env.OAUTH_ISSUER,
  apiCore: process.env.API_CORE_URL,
  apiKey: process.env.API_KEY,
});

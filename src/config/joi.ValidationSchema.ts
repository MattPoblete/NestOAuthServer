import * as Joi from 'joi';

export const JoiValidationSchema = Joi.object({
  environment: Joi.string().default('develop'),
  mongodb: Joi.string(),
  app_port: Joi.number().default(4001),
  jtwSecret: Joi.string(),
  oauthIssuer: Joi.string(),
  apiCore: Joi.string(),
  apiKey: Joi.string(),
});

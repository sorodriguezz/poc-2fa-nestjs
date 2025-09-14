import * as Joi from 'joi';

export const envsConfig = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production').required(),
  PORT: Joi.number().default(3000),
  JWT_ACCESS_SECRET: Joi.string().min(16).required(),
  JWT_ACCESS_TTL: Joi.string().default('1h'),
  JWT_TEMP_SECRET: Joi.string().min(16).required(),
  JWT_TEMP_TTL: Joi.string().default('5m'),
  DB_PATH: Joi.string().required(),
  TWOFA_ENC_KEY_BASE64: Joi.string().min(16).required(),
  ADMIN_EMAIL: Joi.string().email().required(),
  ADMIN_PASSWORD: Joi.string().min(8).required(),
});

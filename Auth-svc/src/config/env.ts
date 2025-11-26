import 'dotenv/config';

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  dbUrl: process.env.DATABASE_URL!,
  jwtIssuer: process.env.JWT_ISSUER || 'auth-service',
  accessTokenTtl: parseInt(process.env.ACCESS_TOKEN_TTL || '60*15*1000', 10),
  refreshTokenDays: parseInt(process.env.REFRESH_TOKEN_DAYS || '30', 10),
  refreshTokenKey: process.env.REFRESH_TOKEN_KEY!,
  privateKeyPath: process.env.RSA_PRIVATE_KEY_PATH!,
  publicKeyPath: process.env.RSA_PUBLIC_KEY_PATH!,
};

import { randomBytes, createHmac } from 'crypto';
import { config } from '../config/env';

export function generateRefreshTokenValue(): string {
  return randomBytes(64).toString('hex'); // 128 chars
}

export function hashRefreshToken(token: string): string {
  return createHmac('sha256', config.refreshTokenKey).update(token).digest('hex');
}

import { pool } from '../db';
import { hashPassword, verifyPassword } from './password';
import { signAccessToken } from './jwt';
import { generateRefreshTokenValue, hashRefreshToken } from './refresh';
import { config } from '../config/env';

export async function createUser(email: string, password: string) {
  const passwordHash = await hashPassword(password);
  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash)
     VALUES ($1, $2)
     RETURNING id, email, token_version, roles`,
    [email, passwordHash]
  );
  return rows[0] as { id: string; email: string; token_version: number; roles: string[] };
}

export async function validateUser(email: string, password: string) {
  const { rows } = await pool.query(
    `SELECT id, email, password_hash, token_version, roles FROM users WHERE email=$1`,
    [email]
  );
  if (!rows.length) return null;
  const user = rows[0];
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return null;
  return { id: user.id, email: user.email, token_version: user.token_version, roles: user.roles as string[] };
}

export async function issueTokensForUser(user: { id: string; token_version: number; roles: string[] }) {
  const accessToken = signAccessToken({
    sub: user.id,
    roles: user.roles,
    token_version: user.token_version,
  });

  const refreshPlain = generateRefreshTokenValue();
  const refreshHash = hashRefreshToken(refreshPlain);
  const expiresAt = new Date(Date.now() + config.refreshTokenDays * 24 * 3600 * 1000);

  const { rows } = await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3) RETURNING id`,
    [user.id, refreshHash, expiresAt]
  );

  return {
    accessToken,
    refreshTokenPlain: refreshPlain,
    refreshTokenId: rows[0].id as string,
  };
}

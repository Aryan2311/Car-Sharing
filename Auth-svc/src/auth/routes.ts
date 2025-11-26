import express from 'express';
import { createUser, validateUser, issueTokensForUser } from './service';
import { hashRefreshToken, generateRefreshTokenValue } from './refresh';
import { pool } from '../db';
import { config } from '../config/env';
import { getJwks } from './jwks';
import { z } from 'zod';

const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(8).max(128),
});

const router = express.Router();

// helpers
function setRefreshCookie(res: express.Response, refreshToken: string) {
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: true, // in prod
    sameSite: 'lax',
    path: '/auth/refresh',
    maxAge: config.refreshTokenDays * 24 * 3600 * 1000,
  });
}

// JWKS endpoint
router.get('/.well-known/jwks.json', async (_req, res) => {
  const jwks = await getJwks();
  res.json(jwks);
});

// Register
router.post('/register', async (req, res) => {
  const parse = loginSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'invalid_payload', details: parse.error.issues });
  }
  const { email, password } = parse.data;
  // basic validation here...
  try {
    const user = await createUser(email, password);
    const { accessToken, refreshTokenPlain } = await issueTokensForUser(user);
    setRefreshCookie(res, refreshTokenPlain);
    res.status(201).json({ accessToken, expiresIn: 15 * 60 });
  } catch (e: any) {
    if (e.code === '23505') return res.status(400).json({ error: 'email_exists' });
    console.error(e);
    res.status(500).json({ error: 'internal' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const parse = loginSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'invalid_payload', details: parse.error.issues });
  }
  const { email, password } = parse.data;
  const user = await validateUser(email, password);
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });

  const { accessToken, refreshTokenPlain } = await issueTokensForUser(user);
  setRefreshCookie(res, refreshTokenPlain);
  res.json({ accessToken, expiresIn: 15 * 60 });
});

// Refresh (simplified: add rotation + reuse detection later)
router.post('/refresh', async (req, res) => {
  const refreshTokenPlain = req.cookies['refresh_token'];
  if (!refreshTokenPlain) return res.status(401).json({ error: 'no_refresh' });

  const hash = hashRefreshToken(refreshTokenPlain);
  const { rows } = await pool.query(
    `SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash=$1`,
    [hash]
  );
  if (!rows.length) return res.status(401).json({ error: 'invalid_refresh' });

  const tokenRow = rows[0];
  if (tokenRow.revoked || new Date(tokenRow.expires_at) < new Date()) {
    return res.status(401).json({ error: 'invalid_refresh' });
  }

  // (Here you should do single-use rotation logic; for now keep it simple)

  // Fetch user
  const u = await pool.query('SELECT id, token_version, roles FROM users WHERE id=$1', [tokenRow.user_id]);
  const user = u.rows[0];

  const { accessToken, refreshTokenPlain: newRefresh } = await issueTokensForUser({
    id: user.id,
    token_version: user.token_version,
    roles: user.roles,
  });

  // revoke old refresh
  await pool.query('UPDATE refresh_tokens SET revoked=true WHERE id=$1', [tokenRow.id]);

  setRefreshCookie(res, newRefresh);
  res.json({ accessToken, expiresIn: 15 * 60 });
});

// Logout
router.post('/logout', async (req, res) => {
  const token = req.cookies['refresh_token'];
  if (token) {
    const hash = hashRefreshToken(token);
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE token_hash=$1', [hash]);
  }
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.status(204).end();
});

// Logout all (global)
router.post('/logout-all', async (req, res) => {
  const userId = req.body.userId; // in real app, take from access token, not body
  await pool.query('UPDATE users SET token_version = token_version + 1 WHERE id=$1', [userId]);
  await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [userId]);
  res.status(204).end();
});

export default router;

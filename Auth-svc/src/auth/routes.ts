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
  
    const refreshHash = hashRefreshToken(refreshTokenPlain);
    const client = await pool.connect();
  
    try {
      await client.query('BEGIN');
  
      const { rows } = await client.query(
        `SELECT id, user_id, expires_at, revoked
         FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE`,
        [refreshHash]
      );
  
      if (!rows.length) {
        // token not found -> can treat as invalid/possible reuse
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'invalid_refresh' });
      }
  
      const tokenRow = rows[0];
  
      if (tokenRow.revoked || new Date(tokenRow.expires_at) < new Date()) {
        // Already revoked or expired
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'invalid_refresh' });
      }
  
      // Fetch user
      const userResult = await client.query(
        'SELECT id, token_version, roles FROM users WHERE id=$1',
        [tokenRow.user_id]
      );
      if (!userResult.rows.length) {
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'user_not_found' });
      }
      const user = userResult.rows[0];
  
      // Issue new tokens (access + refresh)
      const { accessToken, refreshTokenPlain: newRefreshPlain, refreshTokenId } =
        await issueTokensForUser({
          id: user.id,
          token_version: user.token_version,
          roles: user.roles,
        });
  
      // Revoke old refresh token & link replacement
      await client.query(
        `UPDATE refresh_tokens
         SET revoked=true, replaced_by_token=$1
         WHERE id=$2`,
        [refreshTokenId, tokenRow.id]
      );
  
      await client.query('COMMIT');
  
      setRefreshCookie(res, newRefreshPlain);
      return res.json({ accessToken, expiresIn: 5 * 60 });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('refresh error', err);
      return res.status(500).json({ error: 'internal' });
    } finally {
      client.release();
    }
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
  const userId = req.body.user_id; // from access token

  await pool.query('BEGIN');
  try {
    await pool.query(
      'UPDATE users SET token_version = token_version + 1 WHERE id=$1',
      [userId]
    );
    await pool.query(
      'UPDATE refresh_tokens SET revoked=true WHERE user_id=$1',
      [userId]
    );
    await pool.query('COMMIT');
  } catch (e) {
    await pool.query('ROLLBACK');
    console.error(e);
    return res.status(500).json({ error: 'internal' });
  }

  // Clear refresh cookie from this device
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.status(204).end();
});


export default router;

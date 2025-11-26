import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import { config } from '../config/env';

const PRIVATE = fs.readFileSync(path.resolve(config.privateKeyPath), 
'utf8');
const PUBLIC = fs.readFileSync(path.resolve(config.publicKeyPath));

export interface AccessTokenPayload {
  sub: string;          // userId
  roles: string[];
  token_version: number;
}

export function signAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, PRIVATE, {
    algorithm: 'RS256',
    expiresIn: config.accessTokenTtl,
    issuer: config.jwtIssuer,
    keyid: 'key-1', // kid
  });
}

export function getPublicKey() {
  return PUBLIC;
}

import fs from 'fs';
import path from 'path';
import { importSPKI, exportJWK, type JWK } from 'jose';

import { config } from '../config/env';

let jwkCache: { keys: JWK[] } | null = null;

export async function getJwks() {
  if (jwkCache) return jwkCache;

  const publicPem = fs.readFileSync(path.resolve(config.publicKeyPath), 'utf8');
  const publicKey = await importSPKI(publicPem, 'RS256');
  const jwk = await exportJWK(publicKey);
  (jwk as JWK).use = 'sig';
  (jwk as JWK).kid = 'key-1';
  (jwk as JWK).alg = 'RS256';

  jwkCache = { keys: [jwk as JWK] };
  return jwkCache;
}

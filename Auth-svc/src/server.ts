import app from './app';
import { config } from './config/env';
import { runMigrations } from './db';

console.log("TESTS");

async function start() {
  await runMigrations();
  app.get('/', (req, res) => res.send("Hello") );
  app.listen(config.port, () => {
    console.log(`Auth service running on port ${config.port}`);
  });
}

start().catch(err => {
  console.error('Failed to start auth service', err);
  process.exit(1);
});

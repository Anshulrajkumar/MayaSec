import 'dotenv/config';
import { app } from './app.js';

const port = process.env.PORT || 5000;

const server = app.listen(port, () => {
  console.log(`MayaSec backend listening on http://localhost:${port}`);
});

export { app, server };

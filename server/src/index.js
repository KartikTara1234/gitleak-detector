import { app, ensureDemoRepo } from './app.js';
import { storeMode } from './store.js';

const PORT = process.env.PORT || 4000;
ensureDemoRepo().then(() => {
  app.listen(PORT, () => console.log(`Repo Secret Sweeper API on http://localhost:${PORT} (history: ${storeMode()})`));
});

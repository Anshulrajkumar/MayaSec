import { Router } from 'express';
import { getSites, ingestEvents, ingestOptions, streamEvents, checkStatus } from '../controllers/eventController.js';
import { sessionSummary } from '../controllers/aiController.js';
import { requireAuth } from '../middleware/auth.js';

export const eventRouter = Router();

eventRouter.options('/ingest', ingestOptions);
eventRouter.post('/ingest', ingestEvents);
eventRouter.options('/status', ingestOptions);
eventRouter.get('/status', checkStatus);
eventRouter.get('/events/stream', requireAuth, streamEvents);
eventRouter.get('/sites', requireAuth, getSites);
eventRouter.post('/ai/session-summary', requireAuth, sessionSummary);

import { Router } from 'express';
import { getSites, ingestEvents, ingestOptions, streamEvents } from '../controllers/eventController.js';
import { requireAuth } from '../middleware/auth.js';

export const eventRouter = Router();

eventRouter.options('/ingest', ingestOptions);
eventRouter.post('/ingest', ingestEvents);
eventRouter.get('/events/stream', requireAuth, streamEvents);
eventRouter.get('/sites', requireAuth, getSites);

import { Router } from 'express';
import { getRules, addRule, deleteRule } from '../controllers/ruleController.js';
import { requireAuth } from '../middleware/auth.js';

export const ruleRouter = Router();

ruleRouter.get('/', requireAuth, getRules);
ruleRouter.post('/', requireAuth, addRule);
ruleRouter.delete('/:id', requireAuth, deleteRule);

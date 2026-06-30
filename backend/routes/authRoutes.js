import { Router } from 'express';
import {
  addDomain,
  authCallback,
  googleLogin,
  login,
  logout,
  me,
  register,
  removeDomain,
  signup,
  tokenExchange
} from '../controllers/authController.js';
import { requireAppOrigin, requireAuth } from '../middleware/auth.js';

export const authRouter = Router();

authRouter.use(requireAppOrigin);
authRouter.post('/signup', signup);
authRouter.post('/login', login);
authRouter.get('/google', googleLogin);
authRouter.get('/callback', authCallback);
authRouter.get('/token-exchange', tokenExchange);
authRouter.get('/me', requireAuth, me);
authRouter.post('/logout', requireAuth, logout);
authRouter.post('/register', requireAuth, register);
authRouter.post('/domains', requireAuth, addDomain);
authRouter.delete('/domains', requireAuth, removeDomain);

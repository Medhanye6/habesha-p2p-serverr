import { Response, NextFunction } from 'express';
import { AuthRequest } from './authMiddleware.js'; // Import our custom request
import jwt from 'jsonwebtoken';

export const isAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  // We assume 'protect' middleware has already run
  // and attached the user payload
  const user = req.user as jwt.JwtPayload;

  if (user && user.role === 'admin') {
    next(); // User is an admin, proceed
  } else {
    res.status(403).json({ error: 'Forbidden. Admin access required.' });
  }
};

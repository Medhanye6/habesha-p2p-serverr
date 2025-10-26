import { Response, NextFunction } from 'express';
import { AuthRequest } from './authMiddleware.js'; // Import our custom request
import jwt from 'jsonwebtoken';
import db from './db.js'; // Import our database

export const isMerchant = (req: AuthRequest, res: Response, next: NextFunction) => {
  // We assume 'protect' middleware has already run
  const user = req.user as jwt.JwtPayload;

  // 1. Find the merchant application for this user
  const application = db.data.merchants.find(m => m.userId === user.id);

  // 2. Check if they are approved
  if (application && application.status === 'approved') {
    next(); // User is an approved merchant, proceed
  } else {
    res.status(403).json({ error: 'Forbidden. Approved merchant access required.' });
  }
};

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

// This adds a new property 'user' to the Express Request type
// So we can attach the user data to the request
export interface AuthRequest extends Request {
  user?: string | jwt.JwtPayload;
}

export const protect = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  // 1. Check if token exists
  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }

  // 2. Verify the token
  try {
    const jwtSecret = process.env.JWT_SECRET!;
    const decoded = jwt.verify(token, jwtSecret);

    // 3. Attach user info to the request object
    req.user = decoded;

    // 4. Move to the next function
    next();

  } catch (error) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

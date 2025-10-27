import cors from 'cors';
import express, { Request, Response } from 'express'
import bcrypt from 'bcryptjs' // For hashing passwords
import db, { setupDb } from './db.js' // Import our database
import jwt from 'jsonwebtoken'
import 'dotenv/config' // This loads your .env file
import { protect, AuthRequest } from './authMiddleware.js';
import { isAdmin } from './adminMiddleware.js'; 
import { isMerchant } from './merchantMiddleware.js';
import { createServer } from 'http'; // Import Node.js http module
import { Server } from 'socket.io';   // Import socket.io Server 
import crypto from 'crypto'; // For generating random tokens
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

interface PaymentAccount {
    id: number;
    bankName: string;
    accountNumber: string;
    nickname: string;
}


const app = express()
const port = 3001
const httpServer = createServer(app); // Create HTTP server from Express app
const io = new Server(httpServer, {  // Attach socket.io
  cors: {
    origin: "http://localhost:5175", // Allow your frontend to connect
    methods: ["GET", "POST"]
  }
});
app.use(cors({ origin: 'http://localhost:5175' }));
// This tells Express to parse JSON data from incoming requests
app.use(express.json());

// --- API ENDPOINTS ---

// 1. Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.send('Hello from the P2P Server!')
})

// 2. User Registration endpoint
app.post('/register', async (req: Request, res: Response) => {
  try {
    const { email, password, username } = req.body

    // Simple validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' })
    }

    // Check if user already exists
    const existingUser = db.data.users.find((user) => user.email === email)
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' })
    }
    // --- ADD USERNAME CHECK ---
  if (username) {
      const existingUsername = db.data.users.find((user) => user.username === username);
      if (existingUsername) {
          return res.status(400).json({ error: 'Username already taken' });
      }
  }
  // --- END USERNAME CHECK ---

    // Hash the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    // Create new user object
    const newId = db.data.users.length + 1;
    const newUser = {
      id: newId,
      email: email,
      password: hashedPassword,
      username: username || null,
      role: newId === 1 ? 'admin' : 'user', // Add this line
      createdAt: new Date().toISOString(),
    }

    // Add user to the database and save it
    db.data.users.push(newUser)
    await db.write() // This saves the changes to the db.json file

    // Send a success response (don't send the password back!)
    res.status(201).json({
      id: newUser.id,
      email: newUser.email,
    })

  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
})
// 3. User Login endpoint
app.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body

    // 1. Find the user
    const user = db.data.users.find((u) => u.email === email)
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' })
    }

    // 2. Check their password
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' })
    }
    
    // --- ADD 2FA CHECK ---
    await db.read(); // Ensure user data is fresh
    const fullUser = db.data.users.find(u => u.id === user.id); // Get full user data again
    
    if (fullUser?.isTwoFactorEnabled) {
      // 2FA is enabled, DO NOT send token yet.
      // Send a response indicating 2FA is required.
      // We can use a temporary token or just a flag.
      console.log(`2FA required for user: ${email}`);
      return res.status(200).json({ 
        twoFactorRequired: true, 
        message: 'Please enter your 2FA code.' 
        // Optionally include a temporary userId token here if needed for verify step
      });
    }
    // --- END 2FA CHECK ---

    // 3. Create a JWT Token
    const jwtSecret = process.env.JWT_SECRET
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in .env file')
    }

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role, // Add this line
    }

    const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' })

    // 4. Send the token to the user
    res.status(200).json({
      message: 'Logged in successfully',
      token: token,
    })

  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Server error' })
  }
})

// NEW: Verify 2FA code during Login
app.post('/login/2fa', async (req: Request, res: Response) => {
    try {
        const { email, password, token: twoFactorToken } = req.body;

        if (!email || !password || !twoFactorToken) {
            return res.status(400).json({ error: 'Email, password, and 2FA token are required.' });
        }

        // 1. Re-verify email and password
        await db.read();
        const user = db.data.users.find(u => u.email === email);
        if (!user) return res.status(400).json({ error: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });

        // 2. Check if 2FA is actually enabled (should be)
        if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
            return res.status(400).json({ error: '2FA is not enabled for this account.' });
        }

        // 3. Verify the 2FA token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: twoFactorToken,
            window: 1 
        });

        if (!verified) {
            return res.status(400).json({ error: 'Invalid 2FA token.' });
        }

        // 4. Verification successful - Issue the final JWT token
        const jwtSecret = process.env.JWT_SECRET!;
        const payload = { id: user.id, email: user.email, role: user.role };
        const finalToken = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Logged in successfully (2FA verified)',
            token: finalToken,
        });

    } catch (error) {
        console.error("Login 2FA Verify Error:", error);
        res.status(500).json({ error: 'Server error during 2FA login verification.' });
    }
});

// NEW: Forgot Password - Request Reset Token
app.post('/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    await db.read();
    const user = db.data.users.find(u => u.email === email);

    if (!user) {
      // IMPORTANT: Send a generic success message even if user not found
      // This prevents attackers from guessing valid emails.
      return res.status(200).json({ message: 'If an account with that email exists, a reset token has been generated.' });
    }

    // Generate a secure random token
    const resetToken = crypto.randomBytes(32).toString('hex');
    // Set expiry (e.g., 15 minutes from now)
    const resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes in milliseconds

    // Store the hashed token and expiry on the user object
    // In a real DB, hash the token before storing: crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetToken = resetToken; // Store plain token for simplicity NOW
    user.resetTokenExpiry = resetTokenExpiry;

    await db.write();

    // --- SIMULATION ONLY ---
    // In a real app, SEND EMAIL HERE containing the resetToken
    console.log(`Password Reset Token for ${email}: ${resetToken}`); // Log for testing
    res.status(200).json({
       message: 'Reset token generated (SIMULATION - Check server console).',
       // DO NOT RETURN THE TOKEN IN PRODUCTION!
       simulatedTokenForTesting: resetToken
    });
    // --- END SIMULATION ---

  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ error: 'Server error during password reset request.' });
  }
});

// NEW: Reset Password using Token
app.post('/reset-password', async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Valid token and a new password (min 6 chars) are required.' });
    }

    // --- SIMULATION ONLY ---
    // In production, find user by HASHED token:
    // const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    // const user = db.data.users.find(u => u.resetToken === hashedToken && u.resetTokenExpiry > Date.now());

    // Find user by PLAIN token (for simulation)
    await db.read();
    const user = db.data.users.find(u => u.resetToken === token && u.resetTokenExpiry > Date.now());
    // --- END SIMULATION ---

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    // Invalidate the token
    user.resetToken = null;
    user.resetTokenExpiry = null;
    user.updatedAt = new Date().toISOString();

    await db.write();

    res.status(200).json({ message: 'Password has been reset successfully. Please log in.' });

  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ error: 'Server error during password reset.' });
  }
});

// 4. Protected "Get Profile" endpoint
// We add 'protect' middleware as the second argument
// This 'protect' function will run BEFORE the (req, res) => { ... }
app.get('/profile', protect, async (req: AuthRequest, res: Response) => { // Make async
  try {
      const userPayload = req.user as jwt.JwtPayload;
      const userId = userPayload.id as number;

      await db.read(); // Load data

      const user = db.data.users.find(u => u.id === userId);

      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }

      // Exclude password before sending
      const { password: _, ...userWithoutPassword } = user; 
      res.status(200).json(userWithoutPassword); // Send user data

  } catch (error) {
       console.error("Error fetching profile:", error);
       res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// NEW: Initiate 2FA Setup (Protected)
app.post('/2fa/setup', protect, async (req: AuthRequest, res: Response) => {
  try {
    const userPayload = req.user as jwt.JwtPayload;
    const userId = userPayload.id as number;

    await db.read();
    const user = db.data.users.find(u => u.id === userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Generate a new secret if one doesn't exist or force regeneration
    // Store the ascii and base32 versions. base32 is needed for QR code/manual entry.
    const secret = speakeasy.generateSecret({
      name: `HabeshaP2P (${user.email})` // Label shown in authenticator app
    });

    // Temporarily store secret on user for verification step (or handle differently)
    // In production, you might store this temporarily elsewhere until verified.
    user.tempTwoFactorSecret = secret.base32; // Store base32 for QR/manual setup

    await db.write(); // Save the temporary secret

    // Generate QR code data URL
    qrcode.toDataURL(secret.otpauth_url!, (err, data_url) => { // Use the otpauth_url from speakeasy
      if (err) {
        console.error("QR Code generation error:", err);
        return res.status(500).json({ error: 'Failed to generate QR code.' });
      }
      // Send back the secret (for manual entry) and the QR code image data URL
      res.json({
        secret: secret.base32, // For manual entry
        qrCodeUrl: data_url   // Data URL to be rendered as QR code image
      });
    });

  } catch (error) {
    console.error("2FA Setup Error:", error);
    res.status(500).json({ error: 'Server error during 2FA setup.' });
  }
});

// NEW: Verify TOTP and Enable 2FA (Protected)
app.post('/2fa/verify', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { token } = req.body; // The 6-digit code from authenticator app
    const userPayload = req.user as jwt.JwtPayload;
    const userId = userPayload.id as number;

    if (!token) return res.status(400).json({ error: 'Token is required.' });

    await db.read();
    const user = db.data.users.find(u => u.id === userId);
    if (!user || !user.tempTwoFactorSecret) {
      return res.status(400).json({ error: '2FA setup not initiated or user not found.' });
    }

    // Verify the token the user submitted
    const verified = speakeasy.totp.verify({
      secret: user.tempTwoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 1 // Allow 1 step variance (30-90 seconds)
    });

    if (verified) {
      // Verification successful! Enable 2FA permanently.
      user.twoFactorSecret = user.tempTwoFactorSecret; // Move secret to permanent field
      user.isTwoFactorEnabled = true;
      delete user.tempTwoFactorSecret; // Remove temporary secret
      user.updatedAt = new Date().toISOString();
      await db.write();
      res.json({ message: '2FA enabled successfully!' });
    } else {
      // Verification failed
      res.status(400).json({ error: 'Invalid token. Please check your authenticator app and try again.' });
    }
  } catch (error) {
    console.error("2FA Verify Error:", error);
    res.status(500).json({ error: 'Server error during 2FA verification.' });
  }
});

// NEW: Get Essential User Data for Chat/Trade Display (Protected)
app.get('/users/essential', protect, async (req: AuthRequest, res: Response) => {
  try {
    await db.read(); 

    const usersWithoutSensitiveData = db.data.users.map(user => {
      // Only return data needed for public identification and display
      return {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role, // Include role for future checks
        profilePictureUrl: user.profilePictureUrl || null // Add this line 
      };
    });

    res.status(200).json(usersWithoutSensitiveData);

  } catch (error) {
    console.error("Error fetching essential users:", error);
    res.status(500).json({ error: 'Server error fetching essential users' });
  }
});

// NEW: Update User Profile (Protected)
app.put('/profile', protect, async (req: AuthRequest, res: Response) => {
    try {
        const { username } = req.body;
        const userPayload = req.user as jwt.JwtPayload;
        const userId = userPayload.id as number;

        if (!username || typeof username !== 'string' || username.trim().length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters long' });
        }

        const trimmedUsername = username.trim();

        // Ensure data is loaded
        await db.read();

        // Check if username is already taken by someone else
        const existingUsername = db.data.users.find(
            (user) => user.username === trimmedUsername && user.id !== userId
        );
        if (existingUsername) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        // Find the current user in the database
        const currentUser = db.data.users.find(user => user.id === userId);
        if (!currentUser) {
            return res.status(404).json({ error: 'User not found' }); // Should not happen if token is valid
        }

        // Update the username
        currentUser.username = trimmedUsername;
        currentUser.updatedAt = new Date().toISOString(); // Update timestamp

        // Save changes
        await db.write();

        // Return updated user info (excluding password)
        const { password: _, ...userWithoutPassword } = currentUser;
        res.status(200).json({ message: 'Profile updated successfully', user: userWithoutPassword });

    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ error: 'Server error updating profile' });
    }
});

// NEW: Get All Payment Accounts for User (Protected)
app.get('/profile/payments', protect, async (req: AuthRequest, res: Response) => {
  try {
    const userId = (req.user as jwt.JwtPayload).id as number;

    await db.read();
    // Note: We are storing payment accounts directly on the user object for simplicity with lowdb.
    // If they don't exist, return an empty array.
    const accounts = db.data.users.find(u => u.id === userId)?.paymentAccounts || []; 

    res.status(200).json(accounts);
  } catch (error) {
    console.error("Error fetching payment accounts:", error);
    res.status(500).json({ error: 'Server error fetching payment accounts.' });
  }
});

// NEW: Add/Edit Payment Account (Protected)
app.post('/profile/payments', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { id, bankName, accountNumber, nickname } = req.body; // id is optional (for editing)
    const userPayload = req.user as jwt.JwtPayload;
    const userId = userPayload.id as number;

    // Validate required fields
    if (!bankName || !accountNumber || !nickname) {
      return res.status(400).json({ error: 'Bank name, account number, and nickname are required.' });
    }
    
    await db.read(); // Load current data
    const currentUser = db.data.users.find(u => u.id === userId);
    
    if (!currentUser) {
         return res.status(404).json({ error: 'User not found.' });
    }

    // Initialize paymentAccounts array if it doesn't exist
    if (!currentUser.paymentAccounts) {
      currentUser.paymentAccounts = []; 
    }
    
    if (id) {
        // --- EDIT existing account ---
        // Explicitly type the array for safety
        const paymentAccounts = currentUser.paymentAccounts as PaymentAccount[]; 
        const index = paymentAccounts.findIndex((acc) => acc.id === id); 
        
        if (index !== -1) {
            // Update the existing item in the array
            currentUser.paymentAccounts[index] = { id, bankName, accountNumber, nickname };
            await db.write(); // Save changes
            // Send back updated list with 200 OK status
            res.status(200).json({ message: 'Payment account updated successfully.', accounts: currentUser.paymentAccounts }); 
        } else {
             // Account ID provided for edit was not found
             res.status(404).json({ error: 'Payment account not found for editing.' }); 
        }
    } else {
        // --- ADD new account ---
        // Generate a new ID safely (handles deletions)
        const newId = (currentUser.paymentAccounts.length > 0 ? Math.max(...currentUser.paymentAccounts.map((a: PaymentAccount) => a.id)) : 0) + 1; // Add type hint here
        
        // Add the new account to the array
        currentUser.paymentAccounts.push({ id: newId, bankName, accountNumber, nickname });
        await db.write(); // Save changes
        // Send back updated list with 201 Created status
        res.status(201).json({ message: 'Payment account added successfully.', accounts: currentUser.paymentAccounts }); 
    }
  } catch (error) {
    // Handle any unexpected errors during the process
    console.error("Error adding/editing payment account:", error);
    res.status(500).json({ error: 'Server error saving payment account.' });
  }
});

// NEW: Delete Payment Account (Protected)
app.delete('/profile/payments/:accountId', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { accountId: accountIdParam } = req.params;
    const userId = (req.user as jwt.JwtPayload).id as number;

    if (!accountIdParam) {
      return res.status(400).json({ error: 'Account ID is required.' });
    }
    const accountId = parseInt(accountIdParam);

    await db.read();
    const currentUser = db.data.users.find(u => u.id === userId);
    if (!currentUser || !currentUser.paymentAccounts) {
      return res.status(404).json({ error: 'User or accounts not found.' });
    }

    const initialLength = currentUser.paymentAccounts.length;
    // Filter out the account to be deleted
    currentUser.paymentAccounts = (currentUser.paymentAccounts as PaymentAccount[]).filter(
        (acc) => acc.id !== accountId // Now TypeScript knows acc.id is safe
    );

    if (currentUser.paymentAccounts.length === initialLength) {
        return res.status(404).json({ error: 'Payment account not found.' });
    }

    await db.write();

    res.status(200).json({ message: 'Payment account deleted successfully.', accounts: currentUser.paymentAccounts });
  } catch (error) {
    console.error("Error deleting payment account:", error);
    res.status(500).json({ error: 'Server error deleting payment account.' });
  }
});

// NEW: Update User Payment Details (Protected)
app.put('/profile/payment', protect, async (req: AuthRequest, res: Response) => {
    try {
        const { bankName, accountNumber, profilePictureUrl } = req.body;
        const userPayload = req.user as jwt.JwtPayload;
        const userId = userPayload.id as number;

        // Basic validation for bank details
        if (!bankName || !accountNumber) {
            return res.status(400).json({ error: 'Bank name and account number are required for payment setup.' });
        }

        await db.read();
        const currentUser = db.data.users.find(user => user.id === userId);
        if (!currentUser) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Update fields (add them to currentUser, lowdb handles the schema change)
        currentUser.bankName = bankName;
        currentUser.accountNumber = accountNumber;
        currentUser.profilePictureUrl = profilePictureUrl || currentUser.profilePictureUrl || null;
        currentUser.updatedAt = new Date().toISOString();

        await db.write();

        const { password: _, ...userWithoutPassword } = currentUser;
        res.status(200).json({ message: 'Payment profile updated successfully', user: userWithoutPassword });

    } catch (error) {
        console.error("Error updating payment profile:", error);
        res.status(500).json({ error: 'Server error updating payment profile' });
    }
});

// 5. Apply to be a Merchant (Protected)
app.post('/merchant/apply', protect, async (req: AuthRequest, res: Response) => {
  try {
    // Get the user payload from the request (added by our middleware)
    const userPayload = req.user as jwt.JwtPayload;

    // 1. Check if the token is valid and has a user ID
    if (!userPayload || !userPayload.id) {
      return res.status(401).json({ error: 'Invalid user token' });
    }

    const userId = userPayload.id as number;

    // 2. Check if user has already applied
    const existingApplication = db.data.merchants.find(m => m.userId === userId);
    if (existingApplication) {
      return res.status(400).json({ 
        error: 'You have already applied.',
        status: existingApplication.status 
      });
    }

    // 3. Create a new merchant application
    const newMerchantApplication = {
      id: db.data.merchants.length + 1,
      userId: userId,
      status: 'pending', // Admin will approve this later
      createdAt: new Date().toISOString()
    };

    // 4. Save the application to the database
    db.data.merchants.push(newMerchantApplication);
    await db.write();

    // 5. Send success response
    res.status(201).json({
      message: 'Merchant application submitted successfully.',
      application: newMerchantApplication
    });

  } catch (error) {
    console.error(error); // This logs the error to your server terminal
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint to get the current user's merchant application status (Protected)
app.get('/my-merchant-application', protect, async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user as jwt.JwtPayload;

    // 1. Find the application for this user
    const application = db.data.merchants.find(m => m.userId === user.id);

    // 2. If no application exists, send a 404
    if (!application) {
      return res.status(404).json({ error: 'No merchant application found for this user.' });
    }

    // 3. Send the application details (including status)
    res.status(200).json(application);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// NEW: Get All Merchant Applications (Protected + Admin Only)
app.get('/admin/merchant-applications', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    // Return all applications (in a real app, add pagination)
    // Optionally, filter for 'pending' ones if needed on the backend
    const applications = db.data.merchants; 
    res.status(200).json(applications);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// NEW: Get Admin Statistics (Protected + Admin Only)
app.get('/admin/stats', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    // Ensure data is loaded (important for lowdb)
    await db.read(); 

    const totalUsers = db.data.users.length;
    const totalTrades = db.data.trades.length;

    // Count merchant applications by status
    const merchantCounts = db.data.merchants.reduce((acc, app) => {
      acc[app.status] = (acc[app.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>); // { pending: X, approved: Y, rejected: Z }

    // Count trades by status (optional)
    const tradeCounts = db.data.trades.reduce((acc, trade) => {
        acc[trade.status] = (acc[trade.status] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    res.status(200).json({
      totalUsers,
      totalTrades,
      merchantApplicationStatus: merchantCounts,
      tradeStatusCounts: tradeCounts 
    });

  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ error: 'Server error fetching stats' });
  }
});

// NEW: Get All Users (Protected + Admin Only)
app.get('/admin/users', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    await db.read(); // Load current data

    // Exclude passwords before sending
    const usersWithoutPasswords = db.data.users.map(user => {
      const { password, ...userSafeData } = user; // Destructure to remove password
      return userSafeData;
    });

    res.status(200).json(usersWithoutPasswords);

  } catch (error) {
    console.error("Error fetching all users:", error);
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

// NEW: Update User Role/Status (Ban) (Protected + Admin Only)
app.put('/admin/user/:userId/role', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const { userId: userIdParam } = req.params;
    const { newRole } = req.body; // e.g., 'user', 'banned', 'admin'
    const adminId = (req.user as jwt.JwtPayload).id as number;

    if (!userIdParam || !newRole) {
      return res.status(400).json({ error: 'User ID and new role are required.' });
    }
    const userId = parseInt(userIdParam);

    // 1. SECURITY CHECK: Prevent admin from banning themselves
    if (userId === adminId) {
      return res.status(403).json({ error: 'Cannot change your own role.' });
    }

    // 2. Find the user
    await db.read();
    const userToUpdate = db.data.users.find(u => u.id === userId);
    if (!userToUpdate) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // 3. Update the role
    // Note: You should validate newRole against a list (e.g., ['user', 'banned']) in a real app.
    userToUpdate.role = newRole; 
    userToUpdate.updatedAt = new Date().toISOString();

    // 4. Save changes
    await db.write();

    // 5. Return updated list of users (to refresh the frontend table)
    // Re-use logic from GET /admin/users to return safe data
    const usersWithoutPasswords = db.data.users.map(user => {
      const { password, ...userSafeData } = user;
      return userSafeData;
    });

    res.status(200).json({ message: `User ${userId} role updated to ${newRole}.`, users: usersWithoutPasswords });

  } catch (error) {
    console.error("Error banning user:", error);
    res.status(500).json({ error: 'Server error updating user role.' });
  }
});

// NEW: Get All Trades (Protected + Admin Only)
console.log("--- DEBUG: HITTING ADMIN TRADES ENDPOINT ---");
app.get('/admin/trades', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    await db.read(); // Load current data

    // Return all trades (in a real app, add pagination and filtering)
    const trades = db.data.trades; 
    res.status(200).json(trades);

  } catch (error) {
    console.error("Error fetching all trades:", error);
    res.status(500).json({ error: 'Server error fetching trades' });
  }
});

// 6. Admin Approve Merchant (Protected + Admin Only)
// We chain the middleware: 'protect' runs, then 'isAdmin' runs.
app.put('/admin/approve/merchant/:id', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
  const { id } = req.params; // Get the id from the URL

  // 1. Check if an ID was provided
  if (!id) {
    return res.status(400).json({ error: 'Merchant ID is required in the URL' });
  }

  // 2. Now we know 'id' is a string, so we can safely parse it
  const merchantId = parseInt(id);

  // 3. Find the merchant application
    const application = db.data.merchants.find(m => m.id === merchantId);
    if (!application) {
      return res.status(404).json({ error: 'Merchant application not found' });
    }

    // 4. Update its status
    application.status = 'approved';

    // 5. Save to database
    await db.write();

    // 6. Send success response
    res.status(200).json({
      message: 'Merchant application approved.',
      application: application
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});
// NEW: Resolve Dispute (Protected + Admin Only)
app.put('/admin/resolve-trade/:tradeId', protect, isAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const { tradeId: tradeIdParam } = req.params;
    const { resolution } = req.body; // 'release' (to buyer) or 'cancel' (to merchant)

    if (!tradeIdParam || !resolution || !['release', 'cancel'].includes(resolution)) {
      return res.status(400).json({ error: 'Trade ID and a valid resolution ("release" or "cancel") are required.' });
    }
    const tradeId = parseInt(tradeIdParam);

    await db.read();
    const trade = db.data.trades.find(t => t.id === tradeId);
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found.' });
    }

    if (trade.status !== 'disputed') {
        return res.status(400).json({ error: `Trade must be in 'disputed' status to be resolved.` });
    }

    if (resolution === 'cancel') {
        // Admin rules in favor of the Merchant (e.g., buyer never paid)
        trade.status = 'cancelled';

        // Return escrowed amount to the ad (Merchant)
        const originalAd = db.data.ads.find(a => a.id === trade.adId);
        if (originalAd) {
          originalAd.amount += trade.amount;
          originalAd.status = 'active';
        }
    } else if (resolution === 'release') {
        // Admin rules in favor of the Buyer (e.g., buyer provided payment proof)
        trade.status = 'completed';
        // Funds are left with the buyer, which is the final state for 'completed'
    }

    await db.write();

    // Notify both parties and the trade room
    io.to(`trade-${trade.id}`).emit('tradeUpdated', trade);
    io.to(`user-${trade.buyerId}`).emit('myTradesUpdated');
    io.to(`user-${trade.merchantId}`).emit('myTradesUpdated');
    io.emit('adsUpdated'); 

    res.status(200).json({ message: `Trade ${tradeId} resolved. Status set to ${trade.status}.`, trade });

  } catch (error) {
    console.error("Error resolving dispute:", error);
    res.status(500).json({ error: 'Server error resolving dispute.' });
  }
});

// 7. Create an Ad (Protected + Merchant Only)
// We chain three middleware: protect, then check if they are a merchant
app.post('/ads/create', protect, isMerchant, async (req: AuthRequest, res: Response) => {
  try {
    const { type, asset, fiat, price, amount, paymentMethods } = req.body;
    const user = req.user as jwt.JwtPayload;
    const userId = user.id as number;
    
    // --- ADD AD LIMIT CHECK ---
    await db.read(); // Load current data
    const existingActiveAd = db.data.ads.find(
        ad => ad.merchantId === userId && ad.type === type && ad.status === 'active'
    );

    if (existingActiveAd) {
        return res.status(400).json({ 
            error: `You already have an active '${type}' ad. Please edit or delete it first.` 
        });
    }
    // --- END AD LIMIT CHECK ---

    // 1. Basic validation
    if (!type || !asset || !fiat || !price || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // In a real app, you would also add payment methods, etc.

    // 2. Create the new ad
    const newAd = {
      id: db.data.ads.length + 1,
      merchantId: user.id, // The ID of the user posting the ad
      type: type, // "buy" or "sell"
      asset: asset, // "USDT"
      fiat: fiat, // "ETB"
      price: parseFloat(price),
      amount: parseFloat(amount),
      paymentMethods: paymentMethods,
      status: 'active',
      createdAt: new Date().toISOString()
    };

    // 3. Save the ad to the database
    db.data.ads.push(newAd);
    await db.write();
    io.emit('adsUpdated'); // Add this line

    res.status(201).json({
      message: 'Ad created successfully',
      ad: newAd
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// NEW: Edit Ad (Protected + Merchant Only)
app.put('/ads/:adId', protect, isMerchant, async (req: AuthRequest, res: Response) => {
  try {
    const { adId: adIdParam } = req.params;
    const { price, amount, paymentMethods, type, asset, fiat } = req.body; // Get all expected fields
    const user = req.user as jwt.JwtPayload;
    const userId = user.id as number;

    // --- NEW DETAILED VALIDATION ---
    if (!adIdParam) {
        return res.status(400).json({ error: 'Ad ID is required.' });
    }
    const adId = parseInt(adIdParam);
    if (isNaN(adId)) {
        return res.status(400).json({ error: 'Invalid Ad ID.' });
    }

    // Validate price
    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
        return res.status(400).json({ error: 'Invalid or missing price (must be positive).' });
    }
    
    // Validate amount (allow zero, but not negative)
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount < 0) { 
        return res.status(400).json({ error: 'Invalid or missing amount (must be zero or positive).' });
    }
    
    // Validate payment methods
    if (!paymentMethods || !Array.isArray(paymentMethods) || paymentMethods.length === 0) {
        return res.status(400).json({ error: 'At least one payment method is required.' });
    }
    
    // Basic validation for other required fields sent by frontend
    if (!type || !asset || !fiat) {
         return res.status(400).json({ error: 'Type, asset, and fiat are required (should be sent by frontend).' });
    }
    // --- END DETAILED VALIDATION ---

    await db.read(); // Load current data
    const adToUpdate = db.data.ads.find(a => a.id === adId && a.merchantId === userId);

    if (!adToUpdate) {
      return res.status(404).json({ error: 'Ad not found or you are not the owner.' });
    }
    
    // --- Update fields using PARSED values ---
    adToUpdate.price = parsedPrice; 
    adToUpdate.amount = parsedAmount;
    adToUpdate.paymentMethods = paymentMethods; // Assuming paymentMethods is already an array from req.body
    adToUpdate.status = adToUpdate.amount > 0 ? 'active' : 'inactive'; // Update status based on new amount

    // Also update updatedAt timestamp if you have one
    // adToUpdate.updatedAt = new Date().toISOString(); 

    // Save changes to db.json
    await db.write();
    
    // Notify clients via WebSocket
    io.emit('adsUpdated'); 

    // Send successful response
    res.status(200).json({ message: 'Ad updated successfully.', ad: adToUpdate });

  } catch (error) {
    console.error("Error editing ad:", error);
    // Send generic server error response
    res.status(500).json({ error: 'Server error editing ad.' });
  }
});

// NEW: Delete Ad (Protected + Merchant Only)
app.delete('/ads/:adId', protect, isMerchant, async (req: AuthRequest, res: Response) => {
  try {
    const { adId: adIdParam } = req.params;
    const userId = (req.user as jwt.JwtPayload).id as number;

    if (!adIdParam) return res.status(400).json({ error: 'Ad ID is required.' });
    const adId = parseInt(adIdParam);

    await db.read();
    const initialLength = db.data.ads.length;

    // CRITICAL SECURITY: Find the ad and ensure the current user is the merchant
    const adIndex = db.data.ads.findIndex(a => a.id === adId && a.merchantId === userId);

    if (adIndex === -1) {
      return res.status(404).json({ error: 'Ad not found or you are not the owner.' });
    }

    // Remove the ad from the array
    db.data.ads.splice(adIndex, 1);

    await db.write();
    io.emit('adsUpdated'); // Notify everyone

    res.status(200).json({ message: 'Ad deleted successfully.' });
  } catch (error) {
    console.error("Error deleting ad:", error);
    res.status(500).json({ error: 'Server error deleting ad.' });
  }
});

// 8. Get All Active Ads (Public)
app.get('/ads', async (req: Request, res: Response) => {
  // Inside app.get('/ads', ...)
    try {
      await db.read(); // Load fresh data
    
      // Filter for active ads
      const activeAds = db.data.ads.filter(ad => ad.status === 'active');
    
      // Map over active ads to add merchant username
      const adsWithDetails = activeAds.map(ad => {
        // Find the merchant user based on merchantId
        const merchant = db.data.users.find(user => user.id === ad.merchantId);
    
        // Return a new object combining ad data and username
        return {
          ...ad,
          merchantUsername: merchant?.username || merchant?.email || `User #${ad.merchantId}`,
          merchantProfilePic: merchant?.profilePictureUrl || null // Add this line
        };
      });
    
      // In a real app, you might apply backend filters here based on req.query
      // e.g., const { type, paymentMethod } = req.query; ... filter adsWithUsername ...
    
      res.status(200).json(adsWithDetails); // Send the enriched ad data
    
    } catch (error) {
      console.error("Error fetching ads:", error);
      res.status(500).json({ error: 'Server error fetching ads' });
    }
});

// 9. Start a Trade (Protected)
app.post('/trade/start/:adId', protect, async (req: AuthRequest, res: Response) => {
  try {
  const { amount } = req.body;
  const { adId: adIdParam } = req.params; // Get the adId from the URL
  const user = req.user as jwt.JwtPayload;

  // 1. Validate the inputs
  if (!adIdParam) {
    return res.status(400).json({ error: 'Ad ID is required in the URL' });
  }

  const adId = parseInt(adIdParam); // Now it's safe to parse

  // 2. Find the ad
    const ad = db.data.ads.find(a => a.id === adId && a.status === 'active');
    if (!ad) {
      return res.status(404).json({ error: 'Ad not found or is no longer active' });
    }

    // 3. Validate the trade
    if (ad.merchantId === user.id) {
      return res.status(400).json({ error: 'You cannot trade with yourself' });
    }

    const tradeAmount = parseFloat(amount);
    if (!tradeAmount || tradeAmount <= 0) {
      return res.status(400).json({ error: 'Invalid trade amount' });
    }

    if (tradeAmount > ad.amount) {
      return res.status(400).json({ error: 'Trade amount exceeds ad limit' });
    }

// Inside app.post('/trade/start/:adId', ...) try block:
// ... after validating tradeAmount ...

    // 4. Create the new trade object (MODIFIED LOGIC)
    let newTrade: any = {};
    const tradeId = db.data.trades.length + 1; // Generate ID first
    
    if (ad.type === 'sell') { // Merchant is SELLING USDT (User is BUYING)
        newTrade = {
          id: tradeId,
          adId: ad.id,
          buyerId: user.id, // User starting the trade is the buyer
          sellerId: ad.merchantId, // Merchant who posted ad is the seller
          merchantId: ad.merchantId,
          asset: ad.asset,
          fiat: ad.fiat,
          amount: tradeAmount,
          fiatAmount: tradeAmount * ad.price,
          status: 'pending', // Buyer needs to pay ETB
          createdAt: new Date().toISOString()
        };
        // 5. "Escrow" Merchant's funds (Keep existing logic)
        ad.amount -= tradeAmount;
        if (ad.amount <= 0) { ad.status = 'inactive'; }
    
    } else { // Merchant is BUYING USDT (User is SELLING)
         // --- ADD CHECK: Does user have enough USDT? ---
         // This requires actual crypto integration. Placeholder for now.
         // if (!checkUserBalance(user.id, tradeAmount)) {
         //     return res.status(400).json({ error: 'Insufficient USDT balance' });
         // }
         // --- END CHECK ---
    
         newTrade = {
          id: tradeId,
          adId: ad.id,
          buyerId: ad.merchantId, // Merchant who posted ad is the buyer (paying ETB)
          sellerId: user.id, // User starting the trade is the seller (receiving ETB)
          merchantId: ad.merchantId,
          asset: ad.asset,
          fiat: ad.fiat,
          amount: tradeAmount,
          fiatAmount: tradeAmount * ad.price,
          status: 'pending', // Merchant needs to pay ETB
          createdAt: new Date().toISOString()
        };
        // 5. "Escrow" User's funds (Placeholder - needs crypto integration)
        // lockUserFunds(user.id, tradeAmount); 
        // Also reduce the ad's remaining needed amount
        ad.amount -= tradeAmount; 
        if (ad.amount <= 0) { ad.status = 'inactive'; }
    }
    
    
    // 6. Save everything (Keep existing logic)
    db.data.trades.push(newTrade);
    await db.write(); 
    io.emit('adsUpdated');
    // --- ADD THESE LINES ---
    // Notify the buyer and seller individually to update their trade lists
    io.to(`user-${newTrade.buyerId}`).emit('myTradesUpdated'); 
    io.to(`user-${newTrade.sellerId}`).emit('myTradesUpdated');
    // --- END ADD ---
    
    // Adjust success message slightly
    const successMessage = ad.type === 'sell' 
        ? 'Trade started successfully. Please pay the merchant.'
        : 'Trade started successfully. Wait for the merchant to pay you.';
    
    res.status(201).json({
      message: successMessage,
      trade: newTrade
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// NEW: 14. Cancel Trade (Protected)
app.post('/trade/cancel/:tradeId', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { tradeId: tradeIdParam } = req.params;
    const user = req.user as jwt.JwtPayload;

    if (!tradeIdParam) return res.status(400).json({ error: 'Trade ID is required.' });
    const tradeId = parseInt(tradeIdParam);

    await db.read();
    const trade = db.data.trades.find(t => t.id === tradeId);
    if (!trade) return res.status(404).json({ error: 'Trade not found.' });

    /// 1. SECURITY: Only the BUYER can cancel
      if (trade.buyerId !== user.id) {
        return res.status(403).json({ error: 'Only the Buyer can cancel a trade before payment.' });
      }
      
      // 2. CRITICAL RULE: Can only cancel if PENDING (before payment)
      if (trade.status !== 'pending') {
        return res.status(400).json({ error: `Cannot cancel trade in ${trade.status} status.` });
      }

    // 3. Update status
    trade.status = 'cancelled';
    
    // 4. REFUND ESCROW: Find the original ad and return the escrowed amount
    const originalAd = db.data.ads.find(a => a.id === trade.adId);
    if (originalAd) {
      originalAd.amount += trade.amount; // Return funds to the ad's available amount
      originalAd.status = 'active'; // Re-activate ad if it was exhausted
    }

    // 5. Save and notify
    await db.write();
    io.to(`trade-${trade.id}`).emit('tradeUpdated', trade);
    io.to(`user-${trade.buyerId}`).emit('myTradesUpdated');
    io.to(`user-${trade.merchantId}`).emit('myTradesUpdated');
    io.emit('adsUpdated'); // Update everyone's ad list

    res.status(200).json({ message: 'Trade cancelled successfully. Funds returned to ad.', trade });

  } catch (error) {
    console.error("Error cancelling trade:", error);
    res.status(500).json({ error: 'Server error during cancellation.' });
  }
});

// NEW: 15. Initiate Dispute (Protected)
app.post('/trade/dispute/:tradeId', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { tradeId: tradeIdParam } = req.params;
    const user = req.user as jwt.JwtPayload;

    if (!tradeIdParam) return res.status(400).json({ error: 'Trade ID is required.' });
    const tradeId = parseInt(tradeIdParam);

    // In app.post('/trade/dispute/:tradeId', ...)
      // ...
      await db.read();
      const trade = db.data.trades.find(t => t.id === tradeId);
      if (!trade) return res.status(404).json({ error: 'Trade not found.' });
      
      // 1. SECURITY: Check if the user is part of the trade
      if (trade.buyerId !== user.id && trade.merchantId !== user.id) {
          return res.status(403).json({ error: 'Not authorized to dispute this trade.' });
      }
      
      // 2. CRITICAL RULE: Check the status and roles
      if (trade.status === 'paid') {
          // ALLOW DISPUTE: Buyer claims payment sent, Merchant claims payment not received (FRAUD)
          // Both can dispute if status is PAID.
          console.log(`Dispute initiated from user ${user.id} on PAID trade ${tradeId}.`);
      
      } else {
          // Block dispute in other non-critical statuses
          return res.status(400).json({ error: `Trade can only be disputed when status is 'paid'.` });
      }
      
      // 3. Update status (This runs if the status was PAID)
      trade.status = 'disputed'; 

    // 4. Save and notify
    await db.write();
    io.to(`trade-${trade.id}`).emit('tradeUpdated', trade);
    io.to(`user-${trade.buyerId}`).emit('myTradesUpdated');
    io.to(`user-${trade.merchantId}`).emit('myTradesUpdated');
    // Note: You would also notify the Admin here: io.to('role-admin').emit('newDispute', trade.id);

    res.status(200).json({ message: 'Trade successfully marked for administrative review.', trade });

  } catch (error) {
    console.error("Error initiating dispute:", error);
    res.status(500).json({ error: 'Server error initiating dispute.' });
  }
});

// 10. Buyer Confirms Payment (Protected)
app.post('/trade/confirm-payment/:tradeId', protect, async (req: AuthRequest, res: Response) => {
  // Inside app.post('/trade/confirm-payment/:tradeId', ...) try block:
try {
  const { tradeId: tradeIdParam } = req.params; 
  const user = req.user as jwt.JwtPayload;
  console.log(`Confirm Payment Request - User ID: ${user.id}, Trade ID Param: ${tradeIdParam}`); // Log entry
  // --- ADD THIS CHECK ---
    if (!tradeIdParam) {
      return res.status(400).json({ error: 'Trade ID is required in the URL' });
    }
    // --- END CHECK --- 
  
  // ... validation for tradeIdParam ...
  const tradeId = parseInt(tradeIdParam); 

  // 2. Find the trade
  await db.read(); // Read fresh data before finding
  const trade = db.data.trades.find(t => t.id === tradeId);
  if (!trade) {
    console.log("Confirm Payment ERROR: Trade not found."); // Log error
    return res.status(404).json({ error: 'Trade not found' });
  }
  console.log("Confirm Payment: Found trade:", trade); // Log found trade

  // Get the original ad type
  const originalAd = db.data.ads.find(a => a.id === trade.adId);
  if (!originalAd) {
     console.log("Confirm Payment ERROR: Original ad not found."); // Log error
     return res.status(404).json({ error: 'Original ad not found' });
  }
  console.log("Confirm Payment: Ad Type:", originalAd.type); // Log ad type

  // --- REVISED SECURITY CHECK ---
  const isUserMerchant = user.id === trade.merchantId; 
  const isMerchantPaying = originalAd.type === 'buy'; 
  console.log("Confirm Payment: Checks:", { isUserMerchant, isMerchantPaying, tradeStatus: trade.status }); // Log checks

  if (isMerchantPaying) {
      if (!isUserMerchant) {
         console.log("Confirm Payment ERROR: Blocked - Not Merchant for Buy Ad."); // Log block
         return res.status(403).json({ error: 'Only the Merchant confirms payment for this trade type.' });
      }
  } else {
      if (trade.buyerId !== user.id) {
           console.log("Confirm Payment ERROR: Blocked - Not Buyer for Sell Ad."); // Log block
           return res.status(403).json({ error: 'You are not the buyer for this trade.' });
      }
  }
  // --- END REVISED CHECK ---

  // 4. Check status
  if (trade.status !== 'pending') {
    console.log(`Confirm Payment ERROR: Blocked - Trade status is ${trade.status}, not pending.`); // Log block
    return res.status(400).json({ error: 'Trade is not in a pending state' });
  }

  // 5. Update status
  console.log(`Confirm Payment: Updating status from ${trade.status} to paid.`); // Log update intent
  trade.status = 'paid'; 

  // 6. Save to database
  await db.write();
  console.log("Confirm Payment: db.write() completed."); // Log save success

  // --- Emit events (keep existing) ---
  io.to(`trade-${trade.id}`).emit('tradeUpdated', trade); 
  io.to(`user-${trade.buyerId}`).emit('myTradesUpdated');
  io.to(`user-${trade.merchantId}`).emit('myTradesUpdated');
  console.log("Confirm Payment: Emitted WebSocket events."); // Log emits

  res.status(200).json({ /* ... */ });

} catch (error) {
  console.error("Confirm Payment CRASH:", error); // Log crash
  res.status(500).json({ error: 'Server error' });
}
});

// 11. Merchant Releases Funds (Protected)
app.post('/trade/release/:tradeId', protect, async (req: AuthRequest, res: Response) => {
  // Inside app.post('/trade/release/:tradeId', ...) try block:
try {
  const { tradeId: tradeIdParam } = req.params;
  const user = req.user as jwt.JwtPayload;
  console.log(`Release Request - User ID: ${user.id}, Trade ID Param: ${tradeIdParam}`); // Log entry
  
  // --- ADD THIS CHECK ---
    if (!tradeIdParam) {
      return res.status(400).json({ error: 'Trade ID is required in the URL' });
    }
    // --- END CHECK ---

  // ... validation for tradeIdParam ...
  const tradeId = parseInt(tradeIdParam);

  // 2. Find the trade
  await db.read(); // Read fresh data
  const trade = db.data.trades.find(t => t.id === tradeId);
  if (!trade) {
    console.log("Release ERROR: Trade not found."); // Log error
    return res.status(404).json({ error: 'Trade not found' });
  }
  console.log("Release: Found trade:", trade); // Log found trade

  // Get the original ad type
  const originalAd = db.data.ads.find(a => a.id === trade.adId);
  if (!originalAd) {
     console.log("Release ERROR: Original ad not found."); // Log error
     return res.status(404).json({ error: 'Original ad not found' });
  }
  console.log("Release: Ad Type:", originalAd.type); // Log ad type

  // --- REVISED SECURITY CHECK ---
  const isUserMerchant = user.id === trade.merchantId;
  const isMerchantSelling = originalAd.type === 'sell';
  console.log("Release: Security Checks:", { isUserMerchant, isMerchantSelling, isUserSeller: user.id === trade.sellerId }); // Log checks

  if (isMerchantSelling) {
      if (!isUserMerchant) {
         console.log("Release ERROR: Blocked - Not Merchant for Sell Ad."); // Log block
         return res.status(403).json({ error: 'You are not the merchant for this trade.' });
      }
  } else { // Ad type is 'buy'
      if (trade.sellerId !== user.id) {
         console.log("Release ERROR: Blocked - Not Seller for Buy Ad."); // Log block
         return res.status(403).json({ error: 'Only the Seller releases funds for this trade type.' });
      }
  }
  // --- END REVISED CHECK ---

  // 4. Check status
  if (trade.status !== 'paid') {
    console.log(`Release ERROR: Blocked - Trade status is ${trade.status}, not paid.`); // Log block
    return res.status(400).json({ error: 'Trade is not in a paid state.' });
  }

  // 5. Update status
  console.log(`Release: Updating status from ${trade.status} to completed.`); // Log update intent
  trade.status = 'completed';

  // --- Crypto Transfer Placeholder ---
  console.log("Release: Placeholder for actual crypto transfer."); // Log placeholder

  // 6. Save to database
  await db.write();
  console.log("Release: db.write() completed."); // Log save success

  // --- Emit events ---
  io.to(`trade-${trade.id}`).emit('tradeUpdated', trade);
  io.to(`user-${trade.buyerId}`).emit('myTradesUpdated');
  io.to(`user-${trade.merchantId}`).emit('myTradesUpdated'); // Use merchantId here too if relevant
  // Maybe notify seller too if different from merchant?
  if (trade.sellerId !== trade.merchantId) {
       io.to(`user-${trade.sellerId}`).emit('myTradesUpdated');
  }
  console.log("Release: Emitted WebSocket events."); // Log emits

  res.status(200).json({ /* ... */ });

} catch (error) {
  console.error("Release CRASH:", error); // Log crash
  res.status(500).json({ error: 'Server error' });
}
});

// 12. Get a User's Trade History (Protected)
app.get('/my-trades', protect, async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user as jwt.JwtPayload;

    // Find all trades where the user is either the buyer OR the merchant
    const trades = db.data.trades.filter(
      t => t.buyerId === user.id || t.merchantId === user.id || t.sellerId === user.id
    );

    res.status(200).json(trades);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// 13. Get a Single Trade's Details (Protected)
app.get('/trade/:tradeId', protect, async (req: AuthRequest, res: Response) => {
  try {
    const { tradeId: tradeIdParam } = req.params;
    const user = req.user as jwt.JwtPayload;

    if (!tradeIdParam) {
      return res.status(400).json({ error: 'Trade ID is required' });
    }
    const tradeId = parseInt(tradeIdParam);

    // Find the trade
    const trade = db.data.trades.find(t => t.id === tradeId);
    if (!trade) {
      return res.status(44).json({ error: 'Trade not found' });
    }
    
    // --- ADD DEBUG LOG HERE ---
    console.log("Auth Check - /trade/:tradeId:", { 
        userId_from_token: user.id, 
        userRole_from_token: user.role, 
        trade_buyerId: trade.buyerId, 
        trade_sellerId: trade.sellerId,
        is_buyer_match: trade.buyerId === user.id, // Check buyer match
        is_seller_match: trade.sellerId === user.id, // Check seller match
        is_admin: user.role === 'admin' // Check admin role
    });
    // --- END DEBUG LOG ---

    // Check if this user is part of the trade OR if they are an admin
    if (trade.buyerId !== user.id && trade.sellerId !== user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'You are not authorized to view this trade' });
    }
    
    // --- ADD SELLER PAYMENT DETAILS ---
    const sellerUser = db.data.users.find(u => u.id === trade.sellerId);
    const sellerPaymentAccounts = sellerUser?.paymentAccounts || [];
    // --- END ADD ---
    
    // --- ADD MERCHANT PAYMENT DETAILS ---
    const merchantUser = db.data.users.find(u => u.id === trade.merchantId);
    const merchantPaymentAccounts = merchantUser?.paymentAccounts || []; 
    // --- END ADD ---

    // User is part of the trade, send the details
    const adDetails = db.data.ads.find(a => a.id === trade.adId); // Get ad details

    res.status(200).json({
        ...trade, 
        adType: adDetails?.type, // Include the original ad type
        merchantPaymentAccounts: merchantPaymentAccounts, 
        sellerPaymentAccounts: sellerPaymentAccounts // Add seller accounts
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});


// --- START THE SERVER ---

// A function to start the server
async function startServer() {
  await setupDb();
  // Change this line:
  // app.listen(port, () => {
  // To this:
  httpServer.listen(port, () => { // Use httpServer here
    console.log(`🚀 Server is running at http://localhost:${port}`);
    console.log('Database file "db.json" is ready.');
  });
}
// --- Socket.IO Connection Logic ---
io.on('connection', (socket) => {
  console.log('🔌 A user connected:', socket.id);

  // Authenticate socket connection via token
  const token = socket.handshake.auth.token;
  let userId: number | null = null;
  if (token) {
    try {
      const jwtSecret = process.env.JWT_SECRET!;
      const decoded = jwt.verify(token, jwtSecret) as jwt.JwtPayload;
      if (decoded && decoded.id) {
        userId = decoded.id as number;
        // Join a room specific to this user
        socket.join(`user-${userId}`);
        console.log(`User ${userId} (Socket ${socket.id}) joined their room.`);
      }
    } catch (err) {
        // Check if 'err' is an Error object before accessing .message
        if (err instanceof Error) {
          console.error('Socket authentication failed:', err.message);
        } else {
          console.error('Socket authentication failed with unknown error type:', err);
        }
      }
  }

  socket.emit('hello', 'Welcome!'); // Keep the welcome message

// --- Trade Chat Room Logic ---
socket.on('joinTradeRoom', async (tradeId) => { // Make async
  const roomName = `trade-${tradeId}`;
  socket.join(roomName);
  console.log(`User ${userId} (Socket ${socket.id}) joined room ${roomName}`);

  // Load existing messages for this trade
  try {
    await db.read(); // Make sure data is up-to-date
    const trade = db.data.trades.find(t => t.id === tradeId);
    if (trade && trade.chatMessages) {
      // Send only to the user who just joined
      socket.emit('loadMessages', trade.chatMessages);
    } else if (trade && !trade.chatMessages) {
        // Initialize chatMessages if it doesn't exist
        trade.chatMessages = [];
        await db.write();
    }
  } catch (error) {
    console.error("Error loading chat messages:", error);
  }
});

socket.on('sendMessage', async ({ tradeId, message, senderId }) => { // Made async
   const roomName = `trade-${tradeId}`;
   const messageData = {
       text: message,
       senderId: senderId,
       timestamp: new Date().toISOString()
   };

   // 1. Emit to everyone in the room (real-time delivery)
   io.to(roomName).emit('receiveMessage', messageData);

   // 2. Save message to DB
   try {
       await db.read(); // Ensure data is current
       const trade = db.data.trades.find(t => t.id === tradeId);

       if (trade) {
           // Initialize chatMessages array if it doesn't exist
           if (!trade.chatMessages) {
               trade.chatMessages = [];
           }
           trade.chatMessages.push(messageData); // Add new message
           await db.write(); // Save changes to db.json
           console.log(`Message saved for trade ${tradeId}`);
       } else {
           console.error(`Trade ${tradeId} not found for saving message.`);
       }
   } catch (error) {
       console.error("Error saving chat message:", error);
   }
});

socket.on('leaveTradeRoom', (tradeId) => {
    const roomName = `trade-${tradeId}`;
    socket.leave(roomName);
    console.log(`User ${userId} (Socket ${socket.id}) left room ${roomName}`);
});
// --- End Trade Chat Logic ---

  socket.on('disconnect', () => {
    console.log(`🔌 User ${userId} (Socket ${socket.id}) disconnected`);
    // Socket automatically leaves all rooms
  });
});
// --- End Socket.IO Logic ---
// Call the function
startServer()


/**
 * SecureAuth - Cybersecurity Authentication Toolkit
 * Server Implementation (Node.js & Express)
 * 
 * Demonstrates Core Cybersecurity Concepts:
 * 1. Cryptographic Password Hashing & Salting with bcrypt
 * 2. Defense-in-Depth Input Validation (Regex & Character Matrix)
 * 3. Rate Limiting & Brute Force Attack Prevention
 * 4. Stateful Session Authentication with HttpOnly Session Cookies
 * 5. Secure HTTP Response Headers & Protection Against XSS/Clickjacking
 */

const express = require('express');
const session = require('express-session');
let bcrypt;
try {
    bcrypt = require('bcryptjs');
} catch (e) {
    bcrypt = require('bcrypt');
}
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'users.json');

// ==========================================
// 1. SECURITY HEADERS MIDDLEWARE
// ==========================================
// Protects against MIME-type sniffing, Clickjacking, and basic XSS attacks
app.use((req, res, next) => {
    // Prevents browsers from MIME-sniffing a response away from the declared content-type
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Prevents Clickjacking by disallowing the page from being rendered inside an <iframe>
    res.setHeader('X-Frame-Options', 'DENY');
    // Enables the browser's built-in XSS filter
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // Protects referrer information from leaking across domains
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// ==========================================
// 2. PARSING & STATIC ASSET MIDDLEWARE
// ==========================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 3. SECURE SESSION MANAGEMENT
// ==========================================
// Uses express-session to maintain server-side user state without exposing sensitive data
app.use(session({
    // In production, keep this secret in a secure environment variable (.env)
    secret: 'secureauth-cybersecurity-secret-key-2026-xyz',
    resave: false,             // Do not save session if unmodified
    saveUninitialized: false,  // Do not create session until something is stored
    cookie: {
        httpOnly: true,        // Mitigates XSS attacks: JavaScript cannot access document.cookie
        secure: false,         // Set to false for localhost HTTP (set to true in production over HTTPS)
        sameSite: 'lax',       // Mitigates Cross-Site Request Forgery (CSRF)
        maxAge: 1000 * 60 * 60 * 24 // 24 hours session lifetime
    }
}));

// ==========================================
// 4. RATE LIMITING (BRUTE FORCE PROTECTION)
// ==========================================
// In-memory store tracking failed login attempts per client identifier
const loginAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes lockout

function checkRateLimit(key) {
    const now = Date.now();
    const record = loginAttempts.get(key);

    if (!record) return { allowed: true };

    if (now > record.resetTime) {
        loginAttempts.delete(key);
        return { allowed: true };
    }

    if (record.count >= MAX_FAILED_ATTEMPTS) {
        const remainingMinutes = Math.ceil((record.resetTime - now) / 60000);
        return { 
            allowed: false, 
            message: `Too many failed login attempts. Account temporarily locked for security. Please try again in ${remainingMinutes} minute(s).` 
        };
    }

    return { allowed: true };
}

function recordFailedAttempt(key) {
    const now = Date.now();
    const record = loginAttempts.get(key) || { count: 0, resetTime: now + LOCKOUT_WINDOW_MS };
    record.count += 1;
    record.resetTime = now + LOCKOUT_WINDOW_MS;
    loginAttempts.set(key, record);
}

function resetFailedAttempts(key) {
    loginAttempts.delete(key);
}

// ==========================================
// 5. HELPER FUNCTIONS (PERSISTENCE & VALIDATION)
// ==========================================

// Ensure data folder and users.json file exist
function initializeDataStore() {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(DATA_FILE)) {
        fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2), 'utf-8');
    }
}
initializeDataStore();

// Read users from JSON file
function getUsers() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf-8');
        return JSON.parse(data || '[]');
    } catch (err) {
        console.error('Error reading users database:', err.message);
        return [];
    }
}

// Save users to JSON file
function saveUsers(users) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf-8');
        return true;
    } catch (err) {
        console.error('Error saving users database:', err.message);
        return false;
    }
}

// Password Validation Policy
// Required: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character
function validatePassword(password) {
    if (!password || typeof password !== 'string') return false;
    const hasMinLength = password.length >= 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return hasMinLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
}

// Email Validation Regex
function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.trim());
}

// Authentication Middleware to protect routes
function requireAuth(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    return res.status(401).json({
        success: false,
        error: 'Unauthorized: Active session required. Please log in.'
    });
}

// ==========================================
// 6. BACKEND API ROUTES
// ==========================================

/**
 * POST /api/register
 * Registers a new user with bcrypt-hashed password
 */
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        // 1. Validate required fields
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'All fields (Name, Email, Password, Confirm Password) are required.'
            });
        }

        const trimmedName = name.trim();
        const trimmedEmail = email.trim().toLowerCase();

        if (trimmedName.length < 2 || trimmedName.length > 50) {
            return res.status(400).json({
                success: false,
                error: 'Name must be between 2 and 50 characters.'
            });
        }

        // 2. Validate email format
        if (!validateEmail(trimmedEmail)) {
            return res.status(400).json({
                success: false,
                error: 'Please provide a valid email address.'
            });
        }

        // 3. Validate password match
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'Passwords do not match.'
            });
        }

        // 4. Validate password complexity
        if (!validatePassword(password)) {
            return res.status(400).json({
                success: false,
                error: 'Password does not meet security requirements (min 8 chars, uppercase, lowercase, number, and special character).'
            });
        }

        const users = getUsers();

        // 5. Prevent duplicate email registration
        const existingUser = users.find(u => u.email.toLowerCase() === trimmedEmail);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'An account with this email already exists. Please log in.'
            });
        }

        // 6. CYBERSECURITY PRINCIPLE: BCRYPT PASSWORD HASHING
        // Salt rounds: 10 (Generates a cryptographically strong unique salt per user)
        // Never store plaintext passwords in databases or logs!
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // 7. Create user object (Notice: password is NOT saved, only passwordHash)
        const newUser = {
            id: 'usr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9),
            name: trimmedName,
            email: trimmedEmail,
            passwordHash: passwordHash, // Bcrypt hash + salt
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        saveUsers(users);

        // Never return password or passwordHash in API responses
        return res.status(201).json({
            success: true,
            message: 'Registration successful! Your account has been securely created with bcrypt hashing.',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                createdAt: newUser.createdAt
            }
        });

    } catch (err) {
        console.error('Registration error occurred:', err.message);
        return res.status(500).json({
            success: false,
            error: 'An internal server error occurred during registration.'
        });
    }
});

/**
 * POST /api/login
 * Verifies credentials using bcrypt.compare and establishes an authenticated session
 */
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required.'
            });
        }

        const trimmedEmail = email.trim().toLowerCase();
        const rateLimitKey = `${clientIp}_${trimmedEmail}`;

        // 1. Rate Limiting Check (Brute-force protection)
        const rateLimitStatus = checkRateLimit(rateLimitKey);
        if (!rateLimitStatus.allowed) {
            return res.status(429).json({
                success: false,
                error: rateLimitStatus.message
            });
        }

        const users = getUsers();
        const user = users.find(u => u.email.toLowerCase() === trimmedEmail);

        // Security note: To prevent user enumeration attacks, generic error messages are used
        if (!user) {
            recordFailedAttempt(rateLimitKey);
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password.'
            });
        }

        // 2. CYBERSECURITY PRINCIPLE: BCRYPT VERIFICATION
        // bcrypt.compare safely hashes the incoming password with the stored salt
        // and compares the result in constant time to prevent timing attacks.
        const isMatch = await bcrypt.compare(password, user.passwordHash);

        if (!isMatch) {
            recordFailedAttempt(rateLimitKey);
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password.'
            });
        }

        // Reset rate limiter upon successful authentication
        resetFailedAttempts(rateLimitKey);

        // 3. CYBERSECURITY PRINCIPLE: SESSION ESTABLISHMENT
        // Store only safe identity details in session (no password/hash)
        req.session.user = {
            id: user.id,
            name: user.name,
            email: user.email,
            createdAt: user.createdAt,
            loginTime: new Date().toISOString()
        };

        return res.status(200).json({
            success: true,
            message: 'Authentication successful! Session established.',
            user: req.session.user
        });

    } catch (err) {
        console.error('Login error occurred:', err.message);
        return res.status(500).json({
            success: false,
            error: 'An internal server error occurred during login.'
        });
    }
});

/**
 * GET /api/me
 * Returns current authenticated user information from the session
 */
app.get('/api/me', requireAuth, (req, res) => {
    return res.status(200).json({
        success: true,
        authenticated: true,
        sessionId: req.sessionID || ('sess_' + Math.random().toString(36).substring(2, 10).toUpperCase()),
        user: req.session.user,
        sessionDetails: {
            cookieExpires: req.session.cookie.expires,
            httpOnly: req.session.cookie.httpOnly,
            sameSite: req.session.cookie.sameSite,
            maxAge: req.session.cookie.maxAge
        }
    });
});

/**
 * POST /api/logout
 * Destroys user session and clears the session cookie
 */
app.post('/api/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Failed to destroy session.'
                });
            }
            // Clear cookie from client browser
            res.clearCookie('connect.sid');
            return res.status(200).json({
                success: true,
                message: 'Logged out successfully. Session destroyed.'
            });
        });
    } else {
        return res.status(200).json({
            success: true,
            message: 'No active session found.'
        });
    }
});

// ==========================================
// 7. START SERVER
// ==========================================
app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🛡️  SecureAuth – Cybersecurity Authentication Toolkit`);
    console.log(`🚀 Server running at: http://localhost:${PORT}`);
    console.log(`📁 Users data store: ${DATA_FILE}`);
    console.log(`🔐 Bcrypt Hashing: Enabled (10 Salt Rounds)`);
    console.log(`🍪 Session Management: HttpOnly & SameSite Enabled`);
    console.log(`🛑 Rate Limiting: Active (Max 5 attempts / 15 mins)`);
    console.log(`=======================================================`);
});

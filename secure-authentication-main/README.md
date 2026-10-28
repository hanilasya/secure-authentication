# 🛡️ SecureAuth – Cybersecurity Authentication Toolkit

A complete, beginner-friendly cybersecurity laboratory and web application demonstrating secure authentication principles, cryptographic password hashing with **bcrypt**, stateful session management with **express-session**, brute force rate-limiting, and defensive HTTP security headers.

---

## 📌 Project Overview

**SecureAuth** was built as a practical cybersecurity demonstration showing how modern web applications protect user identity, credentials, and sessions. Instead of relying on complex third-party authentication services, this project implements standard industry security patterns directly using Node.js and Express to highlight the underlying mechanics of secure authentication.

---

## 🚀 Key Features

* **Cybersecurity Toolkit Dashboard Interface**:
  * Professional dark cybersecurity terminal aesthetic with cyber-orange accents and green status indicators.
  * Full-width header (`SECUREAUTH :: TOOLKIT`) with live dynamic session ID and `STATUS ONLINE` indicator.
  * Left sidebar module navigation for seamless switching across all 5 security modules.
* **Module 01 — Password Strength Analyzer**:
  * Real-time Shannon entropy calculation and brute-force crack time estimates.
  * 8-Factor security checklist updating on every keystroke:
    1. At least 8 characters
    2. At least 12 characters
    3. Contains uppercase letter (`A-Z`)
    4. Contains lowercase letter (`a-z`)
    5. Contains numeric digit (`0-9`)
    6. Contains special character (`!@#$%^&*...`)
    7. Not a common password (blacklist dictionary check)
    8. No obvious repeated characters (e.g. `aaa`, `111`)
* **Module 02 — User Registration**:
  * Captures User Name, Email, Password, and Password Confirmation.
  * Cryptographic bcrypt password hashing (10 salt rounds) prior to disk persistence.
  * Duplicate email collision detection (HTTP 409).
* **Module 03 — Secure Authentication (Login)**:
  * Constant-time password verification via `bcrypt.compare()`.
  * Rate-limiting brute force protection (5 failed attempts max / 15-minute lockout).
* **Module 04 — Session Security Telemetry**:
  * Stateful session inspection (`express-session`).
  * `HttpOnly` and `SameSite=Lax` cookie verification.
  * **Zero Plaintext Exposure**: passwords and salt hashes are never sent to the browser.
* **Module 05 — Security Architecture Dashboard**:
  * Real-time status matrix showing all 8 enabled security controls with green active badges.
  * Live client-side security event audit console.
* **Defensive HTTP Security Headers**:
  * `X-Content-Type-Options: nosniff` (prevents MIME sniffing)
  * `X-Frame-Options: DENY` (prevents Clickjacking)
  * `X-XSS-Protection: 1; mode=block` (built-in browser XSS filter)

---

## 🛠️ Technologies Used

* **Frontend**:
  * HTML5 (Semantic Structure)
  * Vanilla CSS3 (Dark Cybersecurity / Terminal Theme, Orange Accents, Monospace Typography)
  * Vanilla JavaScript (Live Entropy & Pattern Analysis, Async REST Fetching, Deep-linked Module Navigation)
* **Backend**:
  * **Node.js** (JavaScript Runtime)
  * **Express.js** (Web Server & REST Routing)
  * **bcryptjs / bcrypt** (Cryptographic Salting & Hashing)
  * **express-session** (Secure Stateful Session Management)
* **Storage**:
  * Local JSON File Storage (`data/users.json`)

---

## 📁 Project Structure

```
Secure Authentication/
├── public/
│   ├── index.html         # Master Cybersecurity Toolkit Dashboard (Modules 01-05)
│   ├── register.html      # Compatibility redirect to Module 02
│   ├── dashboard.html     # Compatibility redirect to Module 04 / 05
│   ├── style.css          # Cybersecurity theme styling & responsive layout
│   └── script.js          # Dynamic entropy analyzer, bcrypt API calls, & session telemetry
├── data/
│   └── users.json         # JSON database storing bcrypt hashes (no plaintext passwords)
├── server.js              # Express server with auth routes, bcrypt, sessions, & rate limits
├── package.json           # Node.js project manifest & dependencies
├── .gitignore             # Git ignore rules for node_modules and env files
└── README.md              # Project documentation and cybersecurity guide
```

---

## 🔐 Cybersecurity Concepts Explained

### 1. Password Hashing vs. Encryption
* **Encryption** is *two-way*: ciphertext can be decrypted back into plain text using a key.
* **Hashing** is *one-way*: plaintext is transformed into a fixed-length string that cannot be reversed.

### 2. Why bcrypt with Salt Rounds?
* **Salting**: Generates a random cryptographic salt appended to the password before hashing. This ensures two identical passwords produce completely different hashes, neutralizing **Rainbow Table** precomputation attacks.
* **Work Factor (Salt Rounds)**: bcrypt is intentionally computationally intensive (adaptive cost). Even if attackers dump the database, brute-forcing bcrypt hashes takes exponentially more time than fast algorithms like MD5 or SHA-256.

### 3. Session Security (`HttpOnly` & `SameSite`)
* When a user logs in, the server generates a unique session ID stored in memory and sends it in a cookie (`connect.sid`).
* `httpOnly: true`: The browser prevents client-side JavaScript (`document.cookie`) from reading the cookie, stopping session theft via XSS.
* `sameSite: 'lax'`: The browser does not send cookies on cross-site requests, mitigating CSRF attacks.

### 4. Rate Limiting & Brute Force Prevention
* Attackers often use automated credential stuffing or dictionary attacks to guess credentials.
* SecureAuth tracks failed authentication attempts. Exceeding 5 failed attempts triggers a 15-minute temporary lockout (`HTTP 429 Too Many Requests`).

---

## 📦 Installation & Setup

### Prerequisites
Make sure **Node.js** (v16+) is installed on your computer.

### Step 1: Install Dependencies
Open your terminal inside the project root folder and execute:

```bash
npm install
```

### Step 2: Start the Server
Start the SecureAuth application:

```bash
npm start
```

You will see the console confirmation:
```
=======================================================
🛡️  SecureAuth – Cybersecurity Authentication Toolkit
🚀 Server running at: http://localhost:3000
📁 Users data store: .../data/users.json
🔐 Bcrypt Hashing: Enabled (10 Salt Rounds)
🍪 Session Management: HttpOnly & SameSite Enabled
🛑 Rate Limiting: Active (Max 5 attempts / 15 mins)
=======================================================
```

### Step 3: Open in Browser
Visit the following URL in your web browser:
```
http://localhost:3000
```

---

## 🧪 Step-by-Step Testing Guide

### Test 1: User Registration & Live Password Strength Meter
1. Click **"Register"** or open `http://localhost:3000/register.html`.
2. Type in your name (e.g., `Alex Mercer`) and email (e.g., `alex@cybersecurity.edu`).
3. Start typing in the password field:
   * Notice the live checklist and color-coded meter change from **Weak** (Red) &rarr; **Medium** (Amber) &rarr; **Strong** (Green).
4. Enter a strong password fulfilling all 5 criteria (e.g., `Cyber@Sec2026!`).
5. Confirm the password and click **"Register Account"**.
6. Inspect `data/users.json` in a text editor to verify that only a `$2a$10$...` bcrypt hash is stored—**no plaintext password**.

### Test 2: Duplicate Email Prevention
1. Attempt to register again using the same email (`alex@cybersecurity.edu`).
2. Notice the error: `"An account with this email already exists."`

### Test 3: User Login & Session Creation
1. Navigate to the login page (`http://localhost:3000/index.html`).
2. Enter the registered email and password.
3. Click **"Sign In to Portal"**.
4. You will be redirected to the protected dashboard (`dashboard.html`).

### Test 4: Protected Dashboard Access Control
1. Copy the dashboard URL: `http://localhost:3000/dashboard.html`.
2. Open a new Incognito/Private window and paste the URL.
3. Observe that access is blocked and you are immediately redirected back to `index.html?auth=required`.

### Test 5: Brute Force & Rate Limit Protection
1. On the login page, enter your registered email and intentionally enter an incorrect password **5 times**.
2. On the 5th/6th attempt, notice the HTTP 429 response:
   * `"Too many failed login attempts. Account temporarily locked for security."`

### Test 6: Secure Logout
1. While logged in on `dashboard.html`, click **"Sign Out 🚪"**.
2. The server session is destroyed, the cookie is cleared, and you are redirected back to the login page.
3. Pressing the browser's "Back" button will not allow re-entry into the dashboard without logging in again.

---

## 🎓 College Presentation Notes

When presenting this project to professors or classmates, highlight:
1. **Defense-in-Depth**: Security is implemented across all tiers (UI feedback, server validation, cryptographic storage, session policies, and HTTP headers).
2. **The Anatomy of a Bcrypt Hash**:
   * `$2a$` = Algorithm identifier (bcrypt)
   * `10$` = Cost factor (2^10 iterations)
   * Next 22 characters = Base64-encoded salt
   * Remaining 31 characters = Computed ciphertext
3. **Session vs Token Auth**: Explain why HttpOnly server-managed cookies eliminate token storage vulnerabilities common in `localStorage`.

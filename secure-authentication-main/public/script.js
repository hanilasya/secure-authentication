/**
 * SECUREAUTH :: TOOLKIT — CLIENT LOGIC
 * Cybersecurity Authentication Toolkit
 * 
 * Features:
 * 1. Module navigation and deep linking (01 to 05)
 * 2. Real-time cryptographic password entropy & 8-factor security analyzer
 * 3. User identity registration with Bcrypt (10 rounds) backend API
 * 4. Constant-time login verification & rate limiting defense feedback
 * 5. Session security telemetry, cookie inspection & stateful lifecycle
 * 6. Live security defense audit console
 */

// Common Dictionary for Weak Password Detection
const COMMON_PASSWORDS = new Set([
    'password', 'password123', '123456', '12345678', '123456789', '12345', 
    'admin', 'administrator', 'qwerty', 'welcome', 'letmein', 'iloveyou', 
    'monkey', 'dragon', 'sunshine', 'princess', 'football', 'master', 
    'computer', 'default', 'secret', 'pass123', 'testing123', 'hansika123'
]);

// State
let currentSessionUser = null;
let currentSessionId = 'INIT-' + Math.random().toString(36).substring(2, 6).toUpperCase();

document.addEventListener('DOMContentLoaded', () => {
    initModuleNavigation();
    initPasswordAnalyzer();
    initRegisterModule();
    initLoginModule();
    initSessionSecurityModule();
    initPasswordToggles();
    fetchSessionState();
});

// ==========================================================================
// 1. MODULE NAVIGATION & DEEP LINKING
// ==========================================================================
function initModuleNavigation() {
    const navButtons = document.querySelectorAll('.nav-module-btn');
    const modulePanels = document.querySelectorAll('.module-panel');

    function switchModule(targetId) {
        // Update nav buttons
        navButtons.forEach(btn => {
            if (btn.getAttribute('data-target') === targetId) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Update panels
        modulePanels.forEach(panel => {
            if (panel.id === targetId) {
                panel.classList.add('active');
            } else {
                panel.classList.remove('active');
            }
        });

        // Update URL hash without scrolling
        const hashMap = {
            'module01': '#01-password',
            'module02': '#02-register',
            'module03': '#03-login',
            'module04': '#04-session',
            'module05': '#05-dashboard'
        };
        if (hashMap[targetId]) {
            history.replaceState(null, null, hashMap[targetId]);
        }
    }

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');
            switchModule(target);
            addAuditLog('NAV', `Switched view to [${target.toUpperCase()}]`);
        });
    });

    // Check initial URL hash
    const initialHash = window.location.hash;
    if (initialHash) {
        const hashToModule = {
            '#01-password': 'module01',
            '#02-register': 'module02',
            '#03-login': 'module03',
            '#04-session': 'module04',
            '#05-dashboard': 'module05'
        };
        if (hashToModule[initialHash]) {
            switchModule(hashToModule[initialHash]);
        }
    }

    // Update header session initial display
    const headerSessionEl = document.getElementById('headerSessionId');
    if (headerSessionEl) {
        headerSessionEl.textContent = currentSessionId;
    }
}

// Make switchModule globally accessible for helper transitions
function navigateToModule(moduleId) {
    const btn = document.querySelector(`.nav-module-btn[data-target="${moduleId}"]`);
    if (btn) btn.click();
}

// ==========================================================================
// 2. MODULE 01: PASSWORD STRENGTH ANALYZER (8 CHECKS)
// ==========================================================================
function initPasswordAnalyzer() {
    const passInput = document.getElementById('analyzerPassword');
    const badgeEl = document.getElementById('analyzerStatusBadge');
    const barEl = document.getElementById('analyzerMeterBar');

    const chkLength8 = document.getElementById('chkLength8');
    const chkLength12 = document.getElementById('chkLength12');
    const chkUpper = document.getElementById('chkUpper');
    const chkLower = document.getElementById('chkLower');
    const chkNumber = document.getElementById('chkNumber');
    const chkSpecial = document.getElementById('chkSpecial');
    const chkCommon = document.getElementById('chkCommon');
    const chkRepeats = document.getElementById('chkRepeats');

    const statLength = document.getElementById('statLength');
    const statEntropy = document.getElementById('statEntropy');
    const statCharset = document.getElementById('statCharset');
    const statCrackTime = document.getElementById('statCrackTime');

    if (!passInput) return;

    passInput.addEventListener('input', () => {
        const val = passInput.value;
        const len = val.length;

        if (len === 0) {
            badgeEl.className = 'strength-status-badge';
            badgeEl.textContent = 'NONE';
            barEl.className = 'strength-meter-bar';
            barEl.style.width = '0%';

            [chkLength8, chkLength12, chkUpper, chkLower, chkNumber, chkSpecial, chkCommon, chkRepeats].forEach(c => {
                setCheckValid(c, false);
            });

            if (statLength) statLength.textContent = '0 chars';
            if (statEntropy) statEntropy.textContent = '0 bits';
            if (statCharset) statCharset.textContent = '0 / 4';
            if (statCrackTime) {
                statCrackTime.textContent = 'Instant';
                statCrackTime.className = 'stat-val';
            }
            return;
        }

        // 8 Security Criteria
        const isLen8 = len >= 8;
        const isLen12 = len >= 12;
        const hasUpper = /[A-Z]/.test(val);
        const hasLower = /[a-z]/.test(val);
        const hasNumber = /[0-9]/.test(val);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(val);
        const isNotCommon = !COMMON_PASSWORDS.has(val.toLowerCase());
        const noRepeats = !/(.)\1{2,}/i.test(val); // No 3+ consecutive repeating chars

        // Update Matrix UI
        setCheckValid(chkLength8, isLen8);
        setCheckValid(chkLength12, isLen12);
        setCheckValid(chkUpper, hasUpper);
        setCheckValid(chkLower, hasLower);
        setCheckValid(chkNumber, hasNumber);
        setCheckValid(chkSpecial, hasSpecial);
        setCheckValid(chkCommon, isNotCommon);
        setCheckValid(chkRepeats, noRepeats);

        // Charset Pool Calculation
        let poolSize = 0;
        let poolCount = 0;
        if (hasLower) { poolSize += 26; poolCount++; }
        if (hasUpper) { poolSize += 26; poolCount++; }
        if (hasNumber) { poolSize += 10; poolCount++; }
        if (hasSpecial) { poolSize += 32; poolCount++; }
        if (poolSize === 0) poolSize = 26;

        // Shannon Entropy in bits: L * log2(Pool)
        const entropyBits = Math.round(len * Math.log2(poolSize));

        // Score Evaluation (0 to 8)
        const checkResults = [isLen8, isLen12, hasUpper, hasLower, hasNumber, hasSpecial, isNotCommon, noRepeats];
        const passedCount = checkResults.filter(Boolean).length;

        // Determine Strength Tier
        badgeEl.className = 'strength-status-badge';
        barEl.className = 'strength-meter-bar';

        if (passedCount <= 4 || !isLen8 || !isNotCommon) {
            badgeEl.classList.add('weak');
            badgeEl.textContent = 'WEAK';
            barEl.classList.add('weak');
        } else if (passedCount <= 6 || !isLen12) {
            badgeEl.classList.add('moderate');
            badgeEl.textContent = 'MODERATE';
            barEl.classList.add('moderate');
        } else {
            badgeEl.classList.add('strong');
            badgeEl.textContent = 'STRONG';
            barEl.classList.add('strong');
        }

        // Telemetry Readouts
        if (statLength) statLength.textContent = `${len} chars`;
        if (statEntropy) statEntropy.textContent = `${entropyBits} bits`;
        if (statCharset) statCharset.textContent = `${poolCount} / 4`;
        if (statCrackTime) {
            const crackEstimate = estimateCrackTime(entropyBits);
            statCrackTime.textContent = crackEstimate.time;
            statCrackTime.className = `stat-val ${crackEstimate.color}`;
        }
    });
}

function setCheckValid(element, isValid) {
    if (!element) return;
    const icon = element.querySelector('.check-icon');
    if (isValid) {
        element.classList.add('valid');
        if (icon) icon.textContent = '✓';
    } else {
        element.classList.remove('valid');
        if (icon) icon.textContent = '✕';
    }
}

function estimateCrackTime(entropyBits) {
    if (entropyBits < 28) return { time: '< 1 sec', color: '' };
    if (entropyBits < 45) return { time: 'Few minutes', color: '' };
    if (entropyBits < 60) return { time: '3.5 months', color: 'orange' };
    if (entropyBits < 80) return { time: '450 years', color: 'green' };
    return { time: '10k+ centuries', color: 'green' };
}

// ==========================================================================
// 3. MODULE 02: REGISTER IDENTITY
// ==========================================================================
function initRegisterModule() {
    const regForm = document.getElementById('toolkitRegisterForm');
    const alertBox = document.getElementById('registerAlertBox');
    const submitBtn = document.getElementById('btnRegisterSubmit');

    const regPassInput = document.getElementById('regPassword');
    const regConfirmInput = document.getElementById('regConfirmPassword');
    const regMatchStatus = document.getElementById('regMatchStatus');

    const meterBar = document.getElementById('regMeterBar');
    const meterStatus = document.getElementById('regMeterStatus');

    const reqLen = document.getElementById('regReqLen');
    const reqUpper = document.getElementById('regReqUpper');
    const reqLower = document.getElementById('regReqLower');
    const reqNum = document.getElementById('regReqNum');
    const reqSpec = document.getElementById('regReqSpec');

    if (!regForm) return;

    // Live password strength inside register form
    if (regPassInput) {
        regPassInput.addEventListener('input', () => {
            const val = regPassInput.value;
            const hasLen = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasNum = /[0-9]/.test(val);
            const hasSpec = /[!@#$%^&*(),.?":{}|<>]/.test(val);

            toggleRegReq(reqLen, hasLen);
            toggleRegReq(reqUpper, hasUpper);
            toggleRegReq(reqLower, hasLower);
            toggleRegReq(reqNum, hasNum);
            toggleRegReq(reqSpec, hasSpec);

            if (val.length === 0) {
                meterBar.className = 'reg-meter-bar';
                meterStatus.textContent = 'None';
                meterStatus.style.color = 'var(--text-muted)';
                return;
            }

            const score = [hasLen, hasUpper, hasLower, hasNum, hasSpec].filter(Boolean).length;
            meterBar.className = 'reg-meter-bar';

            if (score <= 2) {
                meterBar.classList.add('weak');
                meterStatus.textContent = 'Weak';
                meterStatus.style.color = 'var(--status-red)';
            } else if (score === 3 || score === 4) {
                meterBar.classList.add('moderate');
                meterStatus.textContent = 'Moderate';
                meterStatus.style.color = 'var(--status-amber)';
            } else {
                meterBar.classList.add('strong');
                meterStatus.textContent = 'Strong';
                meterStatus.style.color = 'var(--status-green)';
            }

            checkPasswordsMatch();
        });
    }

    if (regConfirmInput) {
        regConfirmInput.addEventListener('input', checkPasswordsMatch);
    }

    function checkPasswordsMatch() {
        if (!regConfirmInput || !regPassInput || !regMatchStatus) return;
        const p1 = regPassInput.value;
        const p2 = regConfirmInput.value;

        if (p2.length === 0) {
            regMatchStatus.textContent = '';
            return;
        }

        if (p1 === p2) {
            regMatchStatus.textContent = '✓ PASSWORDS MATCH';
            regMatchStatus.style.color = 'var(--status-green)';
        } else {
            regMatchStatus.textContent = '✕ PASSWORDS DO NOT MATCH';
            regMatchStatus.style.color = 'var(--status-red)';
        }
    }

    function toggleRegReq(el, valid) {
        if (!el) return;
        if (valid) el.classList.add('valid');
        else el.classList.remove('valid');
    }

    // Submit handler
    regForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(alertBox);

        const name = document.getElementById('regName').value.trim();
        const email = document.getElementById('regEmail').value.trim();
        const password = regPassInput.value;
        const confirmPassword = regConfirmInput.value;

        if (!name || !email || !password || !confirmPassword) {
            showAlert(alertBox, 'Validation Error: All fields are required.', 'error');
            return;
        }

        if (password !== confirmPassword) {
            showAlert(alertBox, 'Validation Error: Passwords do not match.', 'error');
            return;
        }

        // Validate password complexity
        const hasLen = password.length >= 8;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNum = /[0-9]/.test(password);
        const hasSpec = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (!hasLen || !hasUpper || !hasLower || !hasNum || !hasSpec) {
            showAlert(alertBox, 'Validation Error: Password does not fulfill all 5 security requirements (min 8 chars, uppercase, lowercase, number, special char).', 'error');
            return;
        }

        setButtonLoading(submitBtn, true, 'Hashing With Bcrypt (10 Rounds)...');

        try {
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password, confirmPassword })
            });

            const data = await res.json();

            if (!res.ok) {
                showAlert(alertBox, `Registration Rejected: ${data.error || 'Request failed.'}`, 'error');
                setButtonLoading(submitBtn, false, 'Initialize & Hash User Credentials');
                addAuditLog('REG_FAIL', `Registration failed for [${email}]: ${data.error}`);
                return;
            }

            // Success feedback
            showAlert(alertBox, `✓ REGISTRATION SUCCESSFUL: User [${data.user.name}] provisioned. Bcrypt hash stored in users.json. Proceeding to Module 03...`, 'success');
            addAuditLog('REG_OK', `Account provisioned for [${data.user.email}] with bcrypt salt hash`, true);
            regForm.reset();
            if (regMatchStatus) regMatchStatus.textContent = '';
            if (meterBar) meterBar.className = 'reg-meter-bar';
            if (meterStatus) meterStatus.textContent = 'None';

            // Pre-fill login email and transition to Module 03
            const loginEmailInput = document.getElementById('loginEmail');
            if (loginEmailInput) loginEmailInput.value = email;

            setTimeout(() => {
                navigateToModule('module03');
                setButtonLoading(submitBtn, false, 'Initialize & Hash User Credentials');
            }, 1600);

        } catch (err) {
            showAlert(alertBox, 'Connection Error: Unable to reach backend server.', 'error');
            setButtonLoading(submitBtn, false, 'Initialize & Hash User Credentials');
        }
    });
}

// ==========================================================================
// 4. MODULE 03: LOGIN & AUTHENTICATION
// ==========================================================================
function initLoginModule() {
    const loginForm = document.getElementById('toolkitLoginForm');
    const alertBox = document.getElementById('loginAlertBox');
    const submitBtn = document.getElementById('btnLoginSubmit');

    if (!loginForm) return;

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(alertBox);

        const email = document.getElementById('loginEmail').value.trim();
        const password = document.getElementById('loginPassword').value;

        if (!email || !password) {
            showAlert(alertBox, 'Authentication Error: Please provide both email and password.', 'error');
            return;
        }

        setButtonLoading(submitBtn, true, 'Verifying Bcrypt Hash & Starting Session...');

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await res.json();

            if (!res.ok) {
                if (res.status === 429) {
                    showAlert(alertBox, `🛑 RATE LIMIT ACTIVE: ${data.error}`, 'error');
                    addAuditLog('BRUTE_DEFENSE', `Rate limit triggered for [${email}] (HTTP 429)`);
                } else {
                    showAlert(alertBox, `Authentication Denied: ${data.error || 'Invalid credentials.'}`, 'error');
                    addAuditLog('AUTH_FAIL', `Invalid login attempt for [${email}]`);
                }
                setButtonLoading(submitBtn, false, 'Authenticate & Establish Session');
                return;
            }

            // Success
            showAlert(alertBox, `🔐 AUTHENTICATION VERIFIED: Session established for [${data.user.name}]. Loading telemetry...`, 'success');
            addAuditLog('AUTH_OK', `Session established for [${data.user.email}]`, true);

            // Fetch session state to update Module 04 and Header
            await fetchSessionState();

            setTimeout(() => {
                navigateToModule('module04');
                setButtonLoading(submitBtn, false, 'Authenticate & Establish Session');
            }, 1000);

        } catch (err) {
            showAlert(alertBox, 'Connection Error: Server unreachable.', 'error');
            setButtonLoading(submitBtn, false, 'Authenticate & Establish Session');
        }
    });
}

// ==========================================================================
// 5. MODULE 04: SESSION SECURITY & TELEMETRY
// ==========================================================================
function initSessionSecurityModule() {
    const refreshBtn = document.getElementById('btnRefreshSession');
    const logoutBtn = document.getElementById('btnSessionLogout');
    const sidebarLogoutBtn = document.getElementById('sidebarLogoutBtn');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            refreshBtn.textContent = 'Polling /api/me...';
            await fetchSessionState();
            refreshBtn.textContent = 'Verify Session [GET /api/me]';
            addAuditLog('SESSION_CHECK', 'Polled /api/me for active express-session validity');
        });
    }

    async function handleLogout() {
        try {
            addAuditLog('LOGOUT', 'Initiating server-side session termination (req.session.destroy)...');
            await fetch('/api/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            currentSessionUser = null;
            currentSessionId = 'GUEST-' + Math.random().toString(36).substring(2, 6).toUpperCase();
            await fetchSessionState();
            addAuditLog('LOGOUT_OK', 'Session destroyed & cookie cleared successfully', true);
            navigateToModule('module03');
        } catch (err) {
            console.error('Logout failed:', err);
        }
    }

    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
    if (sidebarLogoutBtn) sidebarLogoutBtn.addEventListener('click', handleLogout);
}

// Fetch active session from /api/me
async function fetchSessionState() {
    const headerSessionEl = document.getElementById('headerSessionId');
    const statusBadge = document.getElementById('sessionStatusBadge');
    const userGreeting = document.getElementById('sessionUserGreeting');
    const sidebarBadge = document.getElementById('sidebarSessionStateBadge');

    const sessDetailStatus = document.getElementById('sessDetailStatus');
    const sessDetailId = document.getElementById('sessDetailId');
    const sessDetailAuth = document.getElementById('sessDetailAuth');
    const sessDetailUser = document.getElementById('sessDetailUser');
    const sessDetailUserEmail = document.getElementById('sessDetailUserEmail');

    const logoutBtn = document.getElementById('btnSessionLogout');
    const sidebarUserCard = document.getElementById('sidebarUserCard');
    const sidebarUserName = document.getElementById('sidebarUserName');
    const sidebarUserEmail = document.getElementById('sidebarUserEmail');

    try {
        const res = await fetch('/api/me');
        if (res.ok) {
            const data = await res.json();
            currentSessionUser = data.user;
            currentSessionId = data.sessionId || ('SESS-' + data.user.id.substring(4, 10).toUpperCase());

            // Header
            if (headerSessionEl) headerSessionEl.textContent = currentSessionId;

            // Module 04
            if (statusBadge) {
                statusBadge.textContent = 'AUTHENTICATED';
                statusBadge.className = 'session-badge-large authenticated';
            }
            if (userGreeting) {
                userGreeting.textContent = `Verified Identity: ${data.user.name} (${data.user.email})`;
            }
            if (sidebarBadge) {
                sidebarBadge.textContent = 'ACTIVE';
                sidebarBadge.style.color = 'var(--status-green)';
                sidebarBadge.style.borderColor = 'var(--status-green)';
            }

            if (sessDetailStatus) {
                sessDetailStatus.textContent = 'AUTHENTICATED [ACTIVE]';
                sessDetailStatus.className = 'session-detail-val green';
            }
            if (sessDetailId) {
                sessDetailId.textContent = currentSessionId;
                sessDetailId.className = 'session-detail-val orange';
            }
            if (sessDetailAuth) {
                sessDetailAuth.textContent = 'VERIFIED [STATEFUL]';
                sessDetailAuth.className = 'session-detail-val green';
            }
            if (sessDetailUser) {
                sessDetailUser.textContent = `${data.user.name} (${data.user.id})`;
            }
            if (sessDetailUserEmail) {
                sessDetailUserEmail.textContent = `${data.user.email} • Login: ${new Date(data.user.loginTime || Date.now()).toLocaleTimeString()}`;
            }

            if (logoutBtn) logoutBtn.style.display = 'inline-flex';

            // Sidebar User Card
            if (sidebarUserCard) sidebarUserCard.classList.add('visible');
            if (sidebarUserName) sidebarUserName.textContent = data.user.name;
            if (sidebarUserEmail) sidebarUserEmail.textContent = data.user.email;

            return true;

        } else {
            // Unauthenticated
            currentSessionUser = null;
            if (headerSessionEl) headerSessionEl.textContent = currentSessionId;

            if (statusBadge) {
                statusBadge.textContent = 'UNAUTHENTICATED';
                statusBadge.className = 'session-badge-large';
            }
            if (userGreeting) {
                userGreeting.textContent = 'Guest Session (No active login established)';
            }
            if (sidebarBadge) {
                sidebarBadge.textContent = 'GUEST';
                sidebarBadge.style.color = '';
                sidebarBadge.style.borderColor = '';
            }

            if (sessDetailStatus) {
                sessDetailStatus.textContent = 'UNAUTHENTICATED';
                sessDetailStatus.className = 'session-detail-val';
            }
            if (sessDetailId) {
                sessDetailId.textContent = 'NONE';
                sessDetailId.className = 'session-detail-val';
            }
            if (sessDetailAuth) {
                sessDetailAuth.textContent = 'UNVERIFIED';
                sessDetailAuth.className = 'session-detail-val';
            }
            if (sessDetailUser) {
                sessDetailUser.textContent = 'N/A';
            }
            if (sessDetailUserEmail) {
                sessDetailUserEmail.textContent = 'Sign in via Module 03 to populate identity';
            }

            if (logoutBtn) logoutBtn.style.display = 'none';
            if (sidebarUserCard) sidebarUserCard.classList.remove('visible');

            return false;
        }

    } catch (err) {
        console.error('Session verify failed:', err);
        return false;
    }
}

// ==========================================================================
// 6. PASSWORD VISIBILITY TOGGLES
// ==========================================================================
function initPasswordToggles() {
    const toggles = document.querySelectorAll('.toggle-pass-btn, .input-btn-addon');
    toggles.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target') || 'analyzerPassword';
            const input = document.getElementById(targetId);
            if (!input) return;

            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = 'HIDE';
            } else {
                input.type = 'password';
                btn.textContent = 'SHOW';
            }
        });
    });
}

// ==========================================================================
// 7. AUDIT LOG CONSOLE EMITTER (MODULE 05)
// ==========================================================================
function addAuditLog(tag, message, isGreen = false) {
    const container = document.getElementById('auditLogsContainer');
    if (!container) return;

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];

    const line = document.createElement('div');
    line.className = 'audit-line';

    const ts = document.createElement('span');
    ts.className = 'audit-ts';
    ts.textContent = `[${timeStr}]`;

    const tagEl = document.createElement('span');
    tagEl.className = `audit-tag ${isGreen ? 'green' : ''}`;
    tagEl.textContent = `[${tag}]`;

    const msg = document.createElement('span');
    msg.className = 'audit-msg';
    msg.textContent = message;

    line.appendChild(ts);
    line.appendChild(tagEl);
    line.appendChild(msg);

    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

// ==========================================================================
// 8. UI HELPERS
// ==========================================================================
function showAlert(el, msg, type = 'error') {
    if (!el) return;
    el.textContent = msg;
    el.className = `cyber-alert visible ${type}`;
}

function hideAlert(el) {
    if (!el) return;
    el.className = 'cyber-alert';
    el.textContent = '';
}

function setButtonLoading(btn, isLoading, text) {
    if (!btn) return;
    btn.disabled = isLoading;
    btn.textContent = text;
}

// Robust frontend initializer with defensive checks and helpful logs

(function () {
  'use strict';

  // Global error handler to surface uncaught JS errors
  window.addEventListener('error', function (ev) {
    console.error('Unhandled error:', ev.message, ev.error || ev);
  });

  window.addEventListener('unhandledrejection', function (ev) {
    console.error('Unhandled promise rejection:', ev.reason);
  });

  document.addEventListener('DOMContentLoaded', function () {
    try {
      initApp();
    } catch (err) {
      console.error('Error during initApp:', err);
    }
  });

  function initApp() {
    initAuthForms();
    initVaultForm();
    initCheckForms();
    initNotificationToggle();
  }

  // CSRF helper (reads hidden input or global var)
  function getCsrfToken() {
    const el = document.getElementById('csrf_token') || document.querySelector('meta[name="csrf-token"]');
    if (!el) return null;
    return el.value || el.getAttribute('content');
  }

  // --------- Auth forms ----------
  function initAuthForms() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        try {
          const usernameEl = document.getElementById('username');
          const passwordEl = document.getElementById('password');
          if (!usernameEl || !passwordEl) return console.warn('Login inputs missing');
          const payload = { username: usernameEl.value.trim(), password: passwordEl.value };
          const headers = { 'Content-Type': 'application/json' };
          const csrf = getCsrfToken();
          if (csrf) headers['X-CSRFToken'] = csrf;
          const res = await fetch('/login', {
            method: 'POST',
            headers,
            body: JSON.stringify(payload)
          });
          const data = await safeJson(res);
          if (data && data.success) window.location.href = '/dashboard';
          else showFlash('Invalid credentials', 'error');
        } catch (err) {
          console.error('Login error:', err);
          showFlash('Login error', 'error');
        }
      });
    }

    const registerForm = document.getElementById('register-form');
    if (registerForm) {
      registerForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        try {
          const u = document.getElementById('reg-username');
          const p = document.getElementById('reg-password');
          if (!u || !p) return console.warn('Register inputs missing');
          const headers = { 'Content-Type': 'application/json' };
          const csrf = getCsrfToken();
          if (csrf) headers['X-CSRFToken'] = csrf;
          const res = await fetch('/register', {
            method: 'POST',
            headers,
            body: JSON.stringify({ username: u.value.trim(), password: p.value })
          });
          const data = await safeJson(res);
          if (data && data.success) window.location.href = '/dashboard';
          else {
            const msg = data && (data.error || (data.raw && data.raw.message)) || 'Registration failed';
            showFlash(msg, 'error');
          }
        } catch (err) {
          console.error('Register error:', err);
          showFlash('Registration error', 'error');
        }
      });
    }
  }

  // --------- Vault form ----------
  function initVaultForm() {
    const vaultForm = document.getElementById('vault-form');
    if (!vaultForm) return;

    vaultForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      try {
        const label = getValue('label');
        const username = getValue('username');
        const password = getValue('password');
        const email = getValue('email');
        if (!label || !username || !password) {
          showFlash('Label, username and password are required', 'error');
          return;
        }
        const headers = { 'Content-Type': 'application/json' };
        const csrf = getCsrfToken();
        if (csrf) headers['X-CSRFToken'] = csrf;
        const res = await fetch('/add_entry', {
          method: 'POST',
          headers,
          body: JSON.stringify({ label, username, password, email })
        });
        const data = await safeJson(res);
        if (data && data.success) {
          // reload to fetch server-rendered entries (simple & reliable)
          window.location.reload();
        } else {
          showFlash(data && data.error ? data.error : 'Failed to add entry', 'error');
        }
      } catch (err) {
        console.error('Add entry error:', err);
        showFlash('Error adding entry', 'error');
      }
    });
  }

  // --------- Check forms (email/password) ----------
  function initCheckForms() {
    const emailForm = document.getElementById('check-email-form');
    if (emailForm) {
      emailForm.addEventListener('submit', async function (e) {
        // submit normally to let server render results, but protect against missing inputs
        const input = document.getElementById('check-email');
        if (!input) {
          e.preventDefault();
          return console.warn('check-email input missing');
        }
        // allow normal POST submission (server renders)
      });
    }

    const pwdForm = document.getElementById('check-password-form');
    if (pwdForm) {
      pwdForm.addEventListener('submit', async function (e) {
        // allow normal POST submission; just validate presence
        const input = document.getElementById('check-password');
        if (!input) {
          e.preventDefault();
          return console.warn('check-password input missing');
        }
      });
    }
  }

  // --------- Notification toggle (safe) ----------
  function initNotificationToggle() {
    const btn = document.getElementById('notificationBtn');
    const panel = document.getElementById('notificationPanel');
    const closeBtn = document.getElementById('notificationClose');

    if (!btn || !panel) return;

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      panel.classList.toggle('hidden');
    });

    if (closeBtn) {
      closeBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        panel.classList.add('hidden');
      });
    }

    // click outside to close
    document.addEventListener('click', function (e) {
      if (!panel.classList.contains('hidden') && !panel.contains(e.target) && !btn.contains(e.target)) {
        panel.classList.add('hidden');
      }
    });
  }

  // --- vault breach poller (call /api/check-vault) ---
  async function checkVaultBreachesAndRender() {
    try {
      const headers = { 'Accept': 'application/json' };
      const csrf = getCsrfToken();
      if (csrf) headers['X-CSRFToken'] = csrf;
      const res = await fetch('/api/check-vault', { credentials: 'same-origin', headers });
      if (!res.ok) {
        console.warn('check-vault returned', res.status);
        return;
      }
      const data = await res.json();
      const count = data.count || 0;
      const badge = document.getElementById('notificationBadge');
      const content = document.getElementById('notificationContent');
      if (badge) {
        badge.textContent = count > 0 ? String(count) : '';
        if (count > 0) badge.classList.remove('hidden'); else badge.classList.add('hidden');
      }
      if (content) {
        if (!data.breaches || data.breaches.length === 0) {
          content.innerHTML = '<div class="card"><p>No security issues found in your vault.</p></div>';
        } else {
          content.innerHTML = data.breaches.map(b => `
            <div class="breach-item">
              <input type="checkbox" class="breach-checkbox" />
              <div class="breach-body">
                <div class="breach-title">${escapeHtml(b.label || 'Untitled')}</div>
                ${b.email ? `<div class="breach-meta">Email: ${escapeHtml(b.email)} — ${b.email_breaches} breach(es)</div>` : ''}
                ${b.password_breached ? `<div class="breach-meta">Password exposed (${b.password_count || 'unknown'})</div>` : ''}
              </div>
            </div>
          `).join('');
        }
      }
    } catch (err) {
      console.error('Error checking vault breaches:', err);
    }
  }

  // call initially and every 5 minutes
  document.addEventListener('DOMContentLoaded', () => {
    // safe guards
    if (document.getElementById('notificationBtn')) {
      checkVaultBreachesAndRender();
      setInterval(checkVaultBreachesAndRender, 300000);
    }
  });

  // helper (use same escape used elsewhere)
  function escapeHtml(s) { return (s+'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  // --------- Helpers ----------
  function getValue(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : '';
  }

  async function safeJson(response) {
    try {
      return await response.json();
    } catch (err) {
      console.warn('Response JSON parse failed, returning text. Error:', err);
      try { return { raw: await response.text() }; } catch (e) { return null; }
    }
  }

  function showFlash(msg, type = 'info') {
    const container = document.getElementById('flash-container') || createFlashContainer();
    const div = document.createElement('div');
    div.className = `alert alert-${type}`;
    div.textContent = msg;
    container.innerHTML = '';
    container.appendChild(div);
    setTimeout(() => {
      if (div && div.parentNode) div.parentNode.removeChild(div);
    }, 6000);
  }

  function createFlashContainer() {
    const main = document.querySelector('main.container') || document.body;
    const c = document.createElement('div');
    c.id = 'flash-container';
    main.insertBefore(c, main.firstChild);
    return c;
  }

  document.addEventListener('DOMContentLoaded', function () {
    // existing initializers (if any)
    attachDeleteHandlers();
  });

  function attachDeleteHandlers() {
    document.querySelectorAll('.delete-entry-btn').forEach(btn => {
      btn.removeEventListener('click', onDeleteClick);
      btn.addEventListener('click', onDeleteClick);
    });
  }

  async function onDeleteClick(e) {
    const btn = e.currentTarget;
    const label = btn.getAttribute('data-label');
    if (!label) return;
    if (!confirm('Delete entry "' + label + '"?')) return;

    try {
      const headers = { 'Content-Type': 'application/json' };
      const csrf = getCsrfToken();
      if (csrf) headers['X-CSRFToken'] = csrf;
      const res = await fetch('/delete_entry', {
        method: 'POST',
        headers,
        body: JSON.stringify({ label })
      });
      const data = await res.json();
      if (data && data.success) {
        const row = document.querySelector(`.vault-entry[data-label="${CSS.escape(label)}"]`);
        if (row) row.remove();
      } else {
        alert(data && data.error ? data.error : 'Failed to delete entry');
      }
    } catch (err) {
      console.error('Delete error:', err);
      alert('Error deleting entry');
    }
  }

  // Notification handling
  document.addEventListener('DOMContentLoaded', function() {
    const notifBtn = document.getElementById('notificationBtn');
    const sidebar = document.getElementById('notification-sidebar');
    const closeBtn = document.getElementById('closeNotifications');

    if (notifBtn && sidebar) {
        notifBtn.addEventListener('click', () => {
            sidebar.classList.add('active');
            fetchNotifications();
        });
    }

    if (closeBtn && sidebar) {
        closeBtn.addEventListener('click', () => {
            sidebar.classList.remove('active');
        });
    }
});

// --------- Removed sections --------- //
  // - All notification panel event listeners
  // - fetchNotifications function
  // - renderBreaches function
  // - All popup-related DOM manipulation
  // ----------------------------------- //

})(); // close outer IIFE

/* Trust Score UI manager (rotating tips + fetch) */
(function () {
    const tips = [
        "Enable MFA on your primary email",
        "Use unique passwords for each account",
        "Regularly check for password breaches",
        "Keep your software up to date",
        "Be cautious with unknown email links",
        "Back up your important data regularly",
        "Use a password manager for convenience and security",
        "Enable biometric login when possible",
        "Review your security settings monthly",
        "Check your login activity regularly"
    ];

    function getRandomTip() {
        return tips[Math.floor(Math.random() * tips.length)];
    }

    async function fetchTrustScore() {
        try {
            const headers = { 'Accept': 'application/json' };
            const csrf = getCsrfToken();
            if (csrf) headers['X-CSRFToken'] = csrf;
            const res = await fetch('/api/trust-score', { credentials: 'same-origin', headers });
            if (!res.ok) return null;
            const j = await res.json();
            return (typeof j.score === 'number') ? j.score : null;
        } catch (e) {
            console.error('fetchTrustScore error', e);
            return null;
        }
    }

    function colorForScore(score) {
        if (score === null) return 'var(--muted)';
        if (score >= 80) return 'var(--success)';
        if (score >= 50) return 'var(--accent)';
        return 'var(--danger)';
    }

    function initTrustScoreUI() {
        const container = document.querySelector('.trust-score-container');
        if (!container) return;

        const scoreEl = container.querySelector('.trust-score');
        const tipEl = container.querySelector('.security-tip');

        // initial tip
        if (tipEl && !tipEl.textContent.trim()) tipEl.textContent = getRandomTip();

        // rotate tips every 10s with fade
        setInterval(() => {
            if (!tipEl) return;
            tipEl.classList.add('fade');
            setTimeout(() => {
                tipEl.textContent = getRandomTip();
                tipEl.classList.remove('fade');
            }, 420);
        }, 5000);

        // fetch and update score immediately and every 30s
        async function updateScore() {
            const score = await fetchTrustScore();
            if (!scoreEl) return;
            scoreEl.textContent = (typeof score === 'number') ? `Trust Score: ${score}/100` : 'Trust Score: --/100';
            scoreEl.style.color = colorForScore(score);
        }

        updateScore();
        setInterval(updateScore, 30000);
    }

    document.addEventListener('DOMContentLoaded', initTrustScoreUI);
})();

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('password-form');
    if (!form) return;

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const password = document.getElementById('challenge-password').value;
        
        const headers = {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest'
        };
        const csrf = getCsrfToken();
        if (csrf) headers['X-CSRFToken'] = csrf;
        fetch('/vault-challenge', {
            method: 'POST',
          headers,
            body: `password=${encodeURIComponent(password)}`
        })
        .then(response => response.json())
        .then(result => {
            updateChallengeStatus(result);
        })
        .catch(error => console.error('Error:', error));
    });
});

function updateChallengeStatus(result) {
    const status = document.querySelector('.challenge-status');
    if (!status) return;
    
    // Remove old status classes
    status.className = 'challenge-status';
    // Add new status class
    status.classList.add(`status-${result.strength.toLowerCase()}`);
    
    // Update values
    status.innerHTML = `
        <div class="status-item">
            <span class="label">Auth Points</span>
            <span class="value">${result.auth_points}</span>
        </div>
        <div class="status-item">
            <span class="label">Strength</span>
            <span class="value">${result.strength}</span>
        </div>
        <div class="status-item">
            <span class="label">Crack Time</span>
            <span class="value">${result.crack_time}</span>
        </div>
    `;
    
    // Update feedback
    const results = document.querySelector('.challenge-results');
    if (results) {
        results.innerHTML = `
            <div class="result-details">
                <p class="feedback">${result.feedback}</p>
                ${result.breached ? `
                    <p class="breach-warning">
                        ⚠️ This password appears in ${result.breach_count} known breaches
                    </p>
                ` : ''}
            </div>
        `;
    }
}

// Toast notification function
function showToast(message, kind = 'success', timeout = 3500) {
  const t = document.createElement('div');
  t.className = 'site-toast site-toast-' + kind;
  t.textContent = message;
  Object.assign(t.style, {
    position: 'fixed',
    right: '20px',
    bottom: '20px',
    background: 'rgba(0,0,0,0.85)',
    color: '#fff',
    padding: '10px 14px',
    borderRadius: '8px',
    zIndex: 9999,
    boxShadow: '0 4px 12px rgba(0,0,0,0.25)',
    fontSize: '0.95rem'
  });
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.addEventListener('transitionend', () => t.remove()); }, timeout);
}

// Example generic handler for forms that add vault entries
document.addEventListener('submit', function (e) {
  const form = e.target;
  if (form.matches('.vault-entry-form')) { // give your vault add form this class
    e.preventDefault();
    const action = form.action || '/add_entry';
    const fd = new FormData(form);
    fetch(action, { method: 'POST', body: fd, credentials: 'same-origin' })
      .then(r => r.json())
      .then(json => {
        if (json && json.success) {
          showToast(json.message || 'Entry added', 'success');
          form.reset();
          // update UI/vault list as needed
        } else {
          showToast(json.error || 'Failed to add entry', 'error');
        }
      })
      .catch(() => showToast('Network error', 'error'));
  }
});


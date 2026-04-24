/**
 * PrepTracker — Frontend API Client
 * Handles auth token storage, API requests, and page guard.
 * Include this before app.js on every protected page.
 */

(function (global) {
  'use strict';

  const STORAGE_TOKEN = 'pt_token';
  const STORAGE_USER  = 'pt_user';
  const STORAGE_BASE  = 'pt_api_base';

  // ── Helpers ──────────────────────────────────────────────
  function getBase() {
    // If opened from the same origin as the server, use relative URLs.
    const stored = localStorage.getItem(STORAGE_BASE);
    if (stored) return stored;
    // Default: same origin (works when served by server.js)
    return '';
  }

  function setApiBase(base) {
    if (base) localStorage.setItem(STORAGE_BASE, base);
    else localStorage.removeItem(STORAGE_BASE);
  }

  function getToken() {
    return localStorage.getItem(STORAGE_TOKEN) || null;
  }

  function getUser() {
    try { return JSON.parse(localStorage.getItem(STORAGE_USER)); } catch { return null; }
  }

  function setSession(token, user) {
    localStorage.setItem(STORAGE_TOKEN, token);
    localStorage.setItem(STORAGE_USER, JSON.stringify(user));
  }

  function clearSession() {
    localStorage.removeItem(STORAGE_TOKEN);
    localStorage.removeItem(STORAGE_USER);
  }

  // ── Core API fetch ────────────────────────────────────────
  async function api(endpoint, options = {}) {
    const base = getBase();
    const url = base + endpoint;
    const token = getToken();

    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    };

    const res = await fetch(url, { ...options, headers });

    // Handle non-JSON responses
    const contentType = res.headers.get('Content-Type') || '';
    let data;
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data = { error: await res.text() };
    }

    if (!res.ok) {
      // If 401, clear session and redirect to login
      if (res.status === 401) {
        clearSession();
        const current = encodeURIComponent(location.pathname + location.search);
        location.href = `login.html?next=${current}`;
        throw new Error('Session expired. Please login again.');
      }
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    return data;
  }

  // ── Auth guard: call on every protected page ──────────────
  function requireAuth() {
    if (!getToken()) {
      const current = encodeURIComponent(location.pathname + location.search);
      location.href = `login.html?next=${current}`;
      return false;
    }
    return true;
  }

  // ── Apply user info to sidebar shell ─────────────────────
  function applyShell() {
    const user = getUser();
    if (!user) return;

    // Update name & initials wherever they appear
    const nameEls = document.querySelectorAll('.user-name');
    const avatarEls = document.querySelectorAll('.user-avatar');
    const roleEls = document.querySelectorAll('.user-role');

    const initials = (user.name || 'U')
      .split(/\s+/)
      .map(w => w[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);

    nameEls.forEach(el => (el.textContent = user.name || el.textContent));
    avatarEls.forEach(el => (el.textContent = initials));

    // Inject logout button into sidebar footer if not already present
    const footer = document.querySelector('.sidebar-footer');
    if (footer && !footer.querySelector('.logout-btn')) {
      const btn = document.createElement('button');
      btn.className = 'logout-btn';
      btn.innerHTML = '⇠ Sign Out';
      btn.addEventListener('click', () => {
        clearSession();
        location.href = 'login.html';
      });
      footer.appendChild(btn);
    }
  }

  // ── Expose globally as PTAuth ─────────────────────────────
  global.PTAuth = {
    api,
    getToken,
    getUser,
    setSession,
    clearSession,
    requireAuth,
    applyShell,
    getBase,
    setApiBase,
  };

})(window);

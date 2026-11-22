'use strict';
/*
 * ProxyDNS Manager frontend.
 * No external dependencies, no inline scripts (strict CSP).
 * All dynamic text is inserted via textContent – never innerHTML – to rule out XSS.
 */
(() => {
  const S = {
    info: null,       // /api/info
    user: null,       // logged-in user
    csrf: '',         // session-bound CSRF token (server mode)
    token: '',        // bearer token (desktop mode, kept in memory only)
    mfaPending: false,
    configured: false, // Pi-hole + NPM set up; false = setup mode (only settings/account)
    lang: 'de',
    dict: {},
    fallback: {},
  };
  const LANGS = ['de', 'en'];

  // ---------------------------------------------------------------- helpers

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  /**
   * Replaces the children of el. Unlike el.replaceChildren(), null/undefined/false
   * are skipped and arrays are flattened (same rules as h()); the native method
   * would render them as the text "null" or "[object …]".
   */
  function mount(el, ...kids) {
    el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false));
  }

  function t(key, vars) {
    let s = S.dict[key] ?? S.fallback[key] ?? key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split('{' + k + '}').join(String(v));
    return s;
  }

  function errText(err) {
    // Unexpected client-side errors (bugs) show their real message instead of a generic text.
    if (err && !err.code && err.message) return t('err.client', { msg: err.message });
    const code = err && err.code ? err.code : 'internal';
    const key = 'err.' + code;
    const msg = (S.dict[key] ?? S.fallback[key]) ? t(key) : t('err.unknown', { code });
    return err && err.detail ? msg + ' (' + err.detail + ')' : msg;
  }

  function storageGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
  function storageSet(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } }

  function toast(msg, kind = 'ok') {
    const el = h('div', { class: 'toast ' + kind, text: msg });
    document.getElementById('toasts').append(el);
    setTimeout(() => el.remove(), kind === 'err' ? 8000 : 4000);
  }

  function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleString(S.lang === 'de' ? 'de-DE' : 'en-GB');
  }

  /** Button that needs two clicks (no browser dialogs, works in every WebView). */
  function confirmButton(label, armedLabel, onConfirm, cls = 'danger small') {
    let armed = false;
    let timer = null;
    const btn = h('button', { type: 'button', class: cls, text: label });
    btn.addEventListener('click', async () => {
      if (!armed) {
        armed = true;
        btn.textContent = armedLabel;
        btn.classList.add('armed');
        timer = setTimeout(() => { armed = false; btn.textContent = label; btn.classList.remove('armed'); }, 4000);
        return;
      }
      clearTimeout(timer);
      btn.disabled = true;
      try { await onConfirm(); } finally { btn.disabled = false; }
    });
    return btn;
  }

  function field(labelKey, input, hintKey, hintVars) {
    return h('label', { class: 'field' },
      h('span', { text: t(labelKey) }),
      input,
      hintKey ? h('small', { text: t(hintKey, hintVars) }) : null);
  }

  // Required-field marker (*). Inputs get aria-required; HTML `required` is
  // set separately where the browser should enforce it.
  function reqMark() { return h('span', { class: 'req', 'aria-hidden': 'true', text: ' *' }); }

  function reqField(labelKey, input, hintKey, hintVars) {
    input.setAttribute('aria-required', 'true');
    const el = field(labelKey, input, hintKey, hintVars);
    el.firstChild.append(reqMark());
    return el;
  }

  function reqNote() { return h('p', { class: 'muted small', text: t('common.required_note') }); }

  // Grouped section: small title above a rounded group (Apple grouped form).
  function group(title, ...kids) {
    return h('section', { class: 'group' },
      title ? h('h2', { class: 'group-title', text: title }) : null,
      h('div', { class: 'card' }, ...kids));
  }

  // On/off switch for settings that enable a whole feature.
  function switchField(labelKey, input) {
    input.setAttribute('role', 'switch');
    const el = check(labelKey, input);
    el.classList.add('switch');
    return el;
  }

  // Collapsible section (<details>), closed by default.
  function collapsible(summaryText, ...kids) {
    return h('details', { class: 'collapsible' }, h('summary', { text: summaryText }), ...kids);
  }

  function check(labelKey, input) {
    return h('label', { class: 'check' }, input, h('span', { text: t(labelKey) }));
  }

  function alertBox(kind, text) { return h('div', { class: 'alert ' + kind, text }); }

  /** Runs an async form action with button state and error display. */
  async function busy(btn, errBox, fn) {
    if (btn) btn.disabled = true;
    if (errBox) errBox.replaceChildren();
    try {
      await fn();
    } catch (e) {
      if (errBox) errBox.replaceChildren(alertBox('err', errText(e)));
      else toast(errText(e), 'err');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // -------------------------------------------------------------------- API

  async function api(method, path, body) {
    const headers = { 'X-ProxyDNS-Request': '1', Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (S.csrf) headers['X-CSRF-Token'] = S.csrf;
    if (S.token) headers.Authorization = 'Bearer ' + S.token;
    let res;
    try {
      res = await fetch(path, {
        method, headers, credentials: 'same-origin', cache: 'no-store',
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      const e = new Error('network'); e.code = 'network'; throw e;
    }
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      const e = new Error((data && data.error) || 'http_' + res.status);
      e.code = (data && data.error) || 'http_' + res.status;
      e.detail = data && data.detail;
      e.status = res.status;
      e.data = data;
      if (res.status === 401 && e.code === 'unauthorized' && S.user) {
        clearSession();
        toast(t('err.session_expired'), 'err');
        go('login');
      } else if (res.status === 409 && e.code === 'setup_incomplete' && S.user && S.configured) {
        // configuration was removed in the meantime -> back to setup mode
        S.configured = false;
        setTimeout(render, 0);
      }
      throw e;
    }
    return data;
  }

  function setSession(me) {
    S.user = me.user || null;
    S.configured = !!me.configured;
    if (me.csrf) S.csrf = me.csrf;
    if (me.token) S.token = me.token;
    S.mfaPending = false;
  }

  function clearSession() {
    S.user = null; S.csrf = ''; S.token = ''; S.mfaPending = false; S.configured = false;
  }

  // ------------------------------------------------------------------- i18n

  async function loadLang(lang) {
    const get = async (l) => (await fetch('/i18n/' + l + '.json', { cache: 'no-cache' })).json();
    if (!Object.keys(S.fallback).length) S.fallback = await get('de');
    S.dict = lang === 'de' ? S.fallback : await get(lang);
    S.lang = lang;
    document.documentElement.lang = lang;
    storageSet('proxydns.lang', lang);
  }

  function pickLang() {
    const saved = storageGet('proxydns.lang');
    if (LANGS.includes(saved)) return saved;
    const nav = (navigator.language || 'de').slice(0, 2).toLowerCase();
    return LANGS.includes(nav) ? nav : 'en';
  }

  // ---------------------------------------------------------------- routing

  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, '');
    const [path, query] = raw.split('?');
    return { page: path || '', params: new URLSearchParams(query || '') };
  }

  function go(page) {
    if (parseHash().page === page) render();
    else location.hash = '#/' + page;
  }

  const PAGES = {
    entries: { render: pageEntries, nav: 'nav.entries' },
    new: { render: pageNew, nav: 'nav.new' },
    settings: { render: pageSettings, nav: 'nav.settings', admin: true, setup: true },
    users: { render: pageUsers, nav: 'nav.users', admin: true },
    audit: { render: pageAudit, nav: 'nav.audit', admin: true },
    account: { render: pageAccount, nav: 'nav.account' },
  };

  // Pages the current user may open. In setup mode (Pi-hole/NPM not yet
  // configured) only pages marked `setup` are reachable (admins: settings).
  function allowedPages() {
    return Object.keys(PAGES).filter((k) => {
      const d = PAGES[k];
      if (d.admin && S.user.role !== 'admin') return false;
      return S.configured || d.setup;
    });
  }

  function render() {
    const { page, params } = parseHash();
    const main = document.getElementById('app');
    if (S.info.setupRequired) { renderTopbar(null); return pageSetup(main, params); }
    if (S.mfaPending) { renderTopbar(null); return pageMFA(main); }
    if (!S.user) { renderTopbar(null); return pageLogin(main, params); }
    let key = page;
    if (!allowedPages().includes(key)) {
      // setup mode: admins are kept on the settings page, users see a notice
      key = S.configured ? 'entries' : (S.user.role === 'admin' ? 'settings' : null);
      const target = key || 'pending';
      if (page !== target) location.replace('#/' + target);
    }
    renderTopbar(key || 'pending');
    const renderPage = key ? PAGES[key].render : pageSetupPending;
    main.replaceChildren(h('p', { class: 'muted', text: t('common.loading') }));
    Promise.resolve(renderPage(main, params)).catch((e) => {
      main.replaceChildren(alertBox('err', errText(e)));
    });
  }

  function langSelect() {
    const sel = h('select', { 'aria-label': t('common.language'), onchange: async () => { await loadLang(sel.value); render(); } },
      LANGS.map((l) => h('option', { value: l, text: l.toUpperCase() })));
    sel.value = S.lang;
    sel.classList.add('compact');
    return sel;
  }

  // Logged in: sidebar (macOS style, becomes a top bar on narrow windows).
  // Logged out (login, setup, MFA): slim top bar with brand and language.
  function renderTopbar(active) {
    const bar = document.getElementById('topbar');
    const side = document.getElementById('sidebar');
    const withSidebar = !!(S.user && active);
    document.body.classList.toggle('has-sidebar', withSidebar);
    bar.hidden = withSidebar;
    side.hidden = !withSidebar;
    const brand = (label) => h('div', { class: 'brand' }, h('span', { class: 'logo', 'aria-hidden': 'true' }), h('span', { text: label }));
    if (!withSidebar) {
      mount(bar, brand('ProxyDNS Manager'), h('div', { class: 'spacer' }), langSelect());
      side.replaceChildren();
      return;
    }
    // no navigation during initial setup – the settings page is the only page
    const nav = S.configured
      ? h('nav', { 'aria-label': t('nav.main') }, allowedPages().map((k) => h('a', {
        href: '#/' + k, class: 'nav-item' + (k === active ? ' active' : ''), 'aria-current': k === active ? 'page' : null,
      }, h('span', { class: 'ico ico-' + k, 'aria-hidden': 'true' }), h('span', { text: t(PAGES[k].nav) }))))
      : h('p', { class: 'side-note', text: t('nav.setup_mode') });
    const admin = S.user.role === 'admin';
    mount(side,
      brand('ProxyDNS'),
      nav,
      h('div', { class: 'side-foot' },
        h('div', { class: 'who' },
          h('span', { class: 'avatar', 'aria-hidden': 'true', text: S.user.username.slice(0, 1).toUpperCase() }),
          h('div', { class: 'who-text' },
            h('div', { class: 'who-name', text: S.user.username }),
            h('div', { class: 'who-role', text: t(admin ? 'users.role_admin' : 'users.role_user') }))),
        h('div', { class: 'row' },
          langSelect(),
          h('button', { type: 'button', class: 'small', text: t('nav.logout'), onclick: logout }))));
  }

  async function logout() {
    try { await api('POST', '/api/auth/logout'); } catch { /* ignore */ }
    clearSession();
    go('login');
  }

  // ------------------------------------------------------------ auth pages

  function pageSetup(main, params) {
    const err = h('div');
    const token = h('input', { type: 'text', autocomplete: 'off', class: 'mono', value: params.get('token') || '' });
    const user = h('input', { type: 'text', autocomplete: 'username', value: 'admin', required: true });
    const pw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12 });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
    const btn = h('button', { class: 'primary', type: 'submit', text: t('setup.submit') });
    const form = h('form', { class: 'card narrow' },
      h('h1', { text: t('setup.title') }),
      h('p', { class: 'muted', text: t(S.info.setupNeedsCode ? 'setup.intro_server' : 'setup.intro_desktop') }),
      err,
      S.info.setupNeedsCode ? field('setup.code', token, 'setup.code_hint') : null,
      field('common.username', user, 'users.username_hint'),
      field('common.password', pw, 'common.password_hint'),
      field('account.password_repeat', pw2),
      h('div', { class: 'row end' }, btn));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (pw.value !== pw2.value) { err.replaceChildren(alertBox('err', t('err.password_mismatch'))); return; }
      busy(btn, err, async () => {
        const me = await api('POST', '/api/setup', { token: token.value.trim(), username: user.value.trim(), password: pw.value });
        setSession(me);
        S.info.setupRequired = false;
        toast(t('setup.done'));
        history.replaceState(null, '', '#/settings');
        render();
      });
    });
    main.replaceChildren(form);
  }

  function pageLogin(main, params) {
    const err = h('div');
    if (params.get('error')) err.append(alertBox('err', errText({ code: params.get('error') })));
    const user = h('input', { type: 'text', autocomplete: 'username', required: true, autofocus: true });
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const btn = h('button', { class: 'primary', type: 'submit', text: t('login.submit') });
    const oidc = S.info.oidc && S.info.oidc.enabled
      ? [h('div', { class: 'divider', text: t('login.or') }),
        h('a', { class: 'btn oidc-btn', href: '/api/auth/oidc/start', text: S.info.oidc.label || t('login.oidc') })]
      : null;
    const form = h('form', { class: 'card narrow' },
      h('h1', { text: t('login.title') }),
      err,
      field('common.username', user),
      field('common.password', pw),
      h('div', { class: 'row end' }, btn),
      oidc);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(btn, err, async () => {
        const res = await api('POST', '/api/auth/login', { username: user.value.trim(), password: pw.value });
        pw.value = '';
        if (res.mfaRequired) {
          S.csrf = res.csrf || '';
          S.token = res.token || '';
          S.mfaPending = true;
        } else {
          setSession(res);
        }
        history.replaceState(null, '', '#/entries');
        render();
      });
    });
    main.replaceChildren(form);
    user.focus();
  }

  function pageMFA(main) {
    const err = h('div');
    const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]{6,7}', maxlength: 7, required: true, class: 'mono' });
    const btn = h('button', { class: 'primary', type: 'submit', text: t('mfa.submit') });
    const cancel = h('button', { type: 'button', text: t('common.cancel'), onclick: logout });
    const form = h('form', { class: 'card narrow' },
      h('h1', { text: t('mfa.title') }),
      h('p', { class: 'muted', text: t('mfa.intro') }),
      err,
      field('mfa.code', code),
      h('div', { class: 'row end' }, cancel, btn));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(btn, err, async () => {
        try {
          setSession(await api('POST', '/api/auth/totp', { code: code.value }));
        } catch (e) {
          if (e.code === 'mfa_too_many' || e.code === 'unauthorized') { clearSession(); }
          throw e;
        }
        history.replaceState(null, '', '#/entries');
        render();
      });
    });
    main.replaceChildren(form);
    code.focus();
  }

  // Shown to non-admins while Pi-hole/NPM are not configured yet.
  function pageSetupPending(main) {
    main.replaceChildren(h('div', { class: 'card narrow' },
      h('h1', { text: t('pending.title') }),
      h('p', { class: 'muted', text: t('pending.text') })));
  }

  // --------------------------------------------------------------- entries

  async function pageEntries(main) {
    const data = await api('GET', '/api/entries');
    const search = h('input', { type: 'text', placeholder: t('entries.search'), 'aria-label': t('entries.search') });
    search.style.maxWidth = '320px';
    const tbody = h('tbody');
    const count = h('span', { class: 'muted small' });

    const errors = [];
    for (const [backend, info] of Object.entries(data.errors || {})) {
      errors.push(alertBox('err', t('entries.backend_error', { backend: backend === 'npm' ? 'NPM' : 'Pi-hole' }) + ': ' + errText({ code: info.code, detail: info.detail })));
    }

    function status(e) {
      if (e.proxy && e.dnsIps.length && e.pointsToNpm) return h('span', { class: 'badge ok', text: t('entries.status_ok') });
      if (e.proxy && e.dnsIps.length) return h('span', { class: 'badge warn', text: t('entries.status_other_ip') });
      if (e.proxy) return h('span', { class: 'badge warn', text: t('entries.status_proxy_only') });
      return h('span', { class: 'badge', text: t('entries.status_dns_only') });
    }

    function row(e) {
      const p = e.proxy;
      const opts = [];
      if (p) {
        if (!p.enabled) opts.push(h('span', { class: 'badge err', text: t('entries.disabled') }));
        if (p.sslForced) opts.push(h('span', { class: 'badge', text: 'Force SSL' }));
        if (p.http2) opts.push(h('span', { class: 'badge', text: 'HTTP/2' }));
        if (p.hsts) opts.push(h('span', { class: 'badge', text: 'HSTS' }));
        if (p.websocket) opts.push(h('span', { class: 'badge', text: 'WebSocket' }));
        if (p.blockExploits) opts.push(h('span', { class: 'badge', text: t('entries.block_exploits_short') }));
        if (p.caching) opts.push(h('span', { class: 'badge', text: 'Cache' }));
        if (p.accessList) opts.push(h('span', { class: 'badge', text: '🔒 ' + p.accessList }));
      }
      const scheme = p && p.certificate ? 'https://' : 'http://';
      // data-label: column name shown when the table is stacked on narrow windows
      const L = (k) => t('entries.' + k);
      return h('tr', {},
        h('td', { 'data-label': L('domain') }, h('a', { href: scheme + e.domain, target: '_blank', rel: 'noopener noreferrer', text: e.domain })),
        h('td', { class: 'mono nowrap', 'data-label': L('dns'), text: e.dnsIps.join(', ') || '–' }),
        // target with the certificate as secondary line (keeps the table narrow)
        h('td', { 'data-label': L('target') }, p ? h('div', {},
          h('div', { class: 'mono', text: p.forwardScheme + '://' + p.forwardHost + ':' + p.forwardPort }),
          h('div', { class: 'muted small', text: (p.certificate ? '🔒 ' + p.certificate : t('entries.no_cert')) })) : '–'),
        h('td', { 'data-label': L('options') }, opts.length ? h('div', { class: 'badges' }, opts) : null),
        h('td', { class: 'nowrap', 'data-label': L('status') }, status(e)));
    }

    function fill() {
      const q = search.value.trim().toLowerCase();
      const list = data.entries.filter((e) => !q || e.domain.includes(q) || (e.proxy && e.proxy.forwardHost.toLowerCase().includes(q)));
      tbody.replaceChildren(...(list.length ? list.map(row) : [h('tr', {}, h('td', { colspan: 5, class: 'muted center', text: t('entries.empty') }))]));
      count.textContent = t('entries.count', { n: list.length, total: data.entries.length });
    }
    search.addEventListener('input', fill);
    fill();

    mount(main,
      h('div', { class: 'page-head' },
        h('h1', { text: t('entries.title') }), h('div', { class: 'spacer' }),
        h('button', { type: 'button', text: t('common.refresh'), onclick: () => render() }),
        h('a', { class: 'btn primary', href: '#/new', text: '+ ' + t('nav.new') })),
      errors,
      data.targetIp ? null : alertBox('warn', t('entries.no_target_ip')),
      h('div', { class: 'card' },
        h('div', { class: 'row' }, search, h('div', { class: 'spacer' }), count),
        h('div', { class: 'table-wrap' }, h('table', { class: 'stack' },
          h('thead', {}, h('tr', {}, ['entries.domain', 'entries.dns', 'entries.target', 'entries.options', 'entries.status'].map((k) => h('th', { text: t(k) })))),
          tbody))));
  }

  // ------------------------------------------------------------- new entry

  async function pageNew(main) {
    const opt = await api('GET', '/api/entries/options');
    const err = h('div');

    const domain = h('input', { type: 'text', required: true, placeholder: opt.allowedDomains.length ? 'app.' + opt.allowedDomains[0] : 'app.home.lan', autocomplete: 'off', spellcheck: 'false' });
    const scheme = h('select', {}, h('option', { value: 'http', text: 'http' }), h('option', { value: 'https', text: 'https' }));
    const fhost = h('input', { type: 'text', required: true, placeholder: '192.168.1.20', autocomplete: 'off', spellcheck: 'false' });
    const fport = h('input', { type: 'number', required: true, min: 1, max: 65535, placeholder: '8080' });

    const cert = h('select', {}, h('option', { value: '0', text: t('new.no_cert') }),
      opt.certificates.map((c) => h('option', { value: c.id, text: c.name + (c.expires ? ' (' + t('new.expires') + ' ' + c.expires.slice(0, 10) + ')' : '') })));
    const access = h('select', {}, h('option', { value: '0', text: t('new.public') }),
      opt.accessLists.map((a) => h('option', { value: a.id, text: a.name })));

    const cb = (checked) => h('input', { type: 'checkbox', checked });
    const caching = cb(false);
    const blockExploits = cb(true);
    const websocket = cb(true);
    const sslForced = cb(true);
    const http2 = cb(true);
    const hsts = cb(false);
    const hstsSub = cb(false);
    const sslChecks = [sslForced, http2, hsts, hstsSub];

    const advanced = opt.canAdvanced ? h('textarea', { spellcheck: 'false', placeholder: '# nginx' }) : null;

    // Route preview: request → Pi-hole (DNS) → NPM (proxy) → target.
    const preview = h('div', { class: 'route', role: 'group', 'aria-label': t('new.route_label') });
    function updatePreview() {
      const d = domain.value.trim().toLowerCase() || '…';
      const target = (scheme.value) + '://' + (fhost.value.trim() || '…') + ':' + (fport.value || '…');
      const step = (label, value) => h('div', { class: 'route-step' },
        h('span', { class: 'route-label', text: label }),
        h('span', { class: 'route-value mono', text: value }));
      const arrow = () => h('span', { class: 'route-arrow', 'aria-hidden': 'true', text: '→' });
      preview.replaceChildren(
        step(t('new.route_request'), (cert.value !== '0' ? 'https' : 'http') + '://' + d), arrow(),
        step('Pi-hole', d + ' → ' + (opt.targetIp || '?')), arrow(),
        step('NPM', t(cert.value !== '0' ? 'new.route_ssl' : 'new.route_nossl')), arrow(),
        step(t('new.route_target'), target));
    }
    function updateSSL() {
      const has = cert.value !== '0';
      for (const c of sslChecks) {
        c.disabled = !has;
        c.closest('label').classList.toggle('disabled', !has);
      }
      hstsSub.disabled = !has || !hsts.checked;
      hstsSub.closest('label').classList.toggle('disabled', hstsSub.disabled);
      updatePreview();
    }

    // custom locations
    const locBox = h('div');
    const locations = [];
    function addLocation() {
      const l = {
        path: h('input', { type: 'text', placeholder: '/api', spellcheck: 'false' }),
        scheme: h('select', {}, h('option', { value: 'http', text: 'http' }), h('option', { value: 'https', text: 'https' })),
        host: h('input', { type: 'text', placeholder: '192.168.1.21', spellcheck: 'false' }),
        port: h('input', { type: 'number', min: 1, max: 65535, placeholder: '80' }),
        adv: opt.canAdvanced ? h('textarea', { spellcheck: 'false', placeholder: '# nginx' }) : null,
      };
      const box = h('div', { class: 'location' },
        h('div', { class: 'grid2' },
          reqField('new.loc_path', l.path),
          field('new.forward_scheme', l.scheme),
          reqField('new.forward_host', l.host),
          reqField('new.forward_port', l.port)),
        l.adv ? collapsible(t('new.advanced'), l.adv) : null,
        h('div', { class: 'row end' }, h('button', {
          type: 'button', class: 'danger small', text: t('common.remove'),
          onclick: () => { locations.splice(locations.indexOf(l), 1); box.remove(); },
        })));
      locations.push(l);
      locBox.append(box);
    }

    for (const el of [domain, fhost, fport, scheme]) el.addEventListener('input', updatePreview);
    cert.addEventListener('change', updateSSL);
    hsts.addEventListener('change', updateSSL);

    const btn = h('button', { class: 'primary', type: 'submit', text: t('new.submit') });
    const form = h('form', {},
      h('h1', { text: t('new.title') }),
      reqNote(),
      err,
      group(t('new.section_domain'),
        reqField('new.domain', domain, opt.allowedDomains.length ? 'new.domain_hint_allowed' : 'new.domain_hint', { list: opt.allowedDomains.join(', ') })),
      group(t('new.section_target'),
        h('div', { class: 'grid2' },
          field('new.forward_scheme', scheme),
          reqField('new.forward_host', fhost, 'new.forward_host_hint'),
          reqField('new.forward_port', fport)),
        preview),
      h('div', { class: 'grid2' },
        group(t('new.section_options'),
          check('new.caching', caching),
          check('new.block_exploits', blockExploits),
          check('new.websocket', websocket),
          field('new.access_list', access)),
        group('SSL',
          field('new.certificate', cert, 'new.certificate_hint'),
          check('new.ssl_forced', sslForced),
          check('new.http2', http2),
          check('new.hsts', hsts),
          check('new.hsts_sub', hstsSub))),
      group(t('new.section_locations'),
        locBox,
        h('button', { type: 'button', class: 'small', text: '+ ' + t('new.add_location'), onclick: addLocation })),
      advanced ? group(null,
        collapsible(t('new.advanced'),
          alertBox('warn', t('new.advanced_warning')),
          advanced)) : null,
      h('div', { class: 'row end' }, h('a', { class: 'btn', href: '#/entries', text: t('common.cancel') }), btn));

    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const body = {
        domain: domain.value.trim(),
        forwardScheme: scheme.value,
        forwardHost: fhost.value.trim(),
        forwardPort: parseInt(fport.value, 10) || 0,
        certificateId: parseInt(cert.value, 10) || 0,
        sslForced: sslForced.checked,
        http2Support: http2.checked,
        hstsEnabled: hsts.checked,
        hstsSubdomains: hstsSub.checked,
        blockExploits: blockExploits.checked,
        cachingEnabled: caching.checked,
        websocket: websocket.checked,
        accessListId: parseInt(access.value, 10) || 0,
        advancedConfig: advanced ? advanced.value : '',
        locations: locations.map((l) => ({
          path: l.path.value.trim(),
          forwardScheme: l.scheme.value,
          forwardHost: l.host.value.trim(),
          forwardPort: parseInt(l.port.value, 10) || 0,
          advancedConfig: l.adv ? l.adv.value : '',
        })),
      };
      busy(btn, err, async () => {
        const res = await api('POST', '/api/entries', body);
        toast(t('new.created', { domain: res.domain }));
        go('entries');
      }).then(() => { if (err.childElementCount) err.scrollIntoView({ behavior: 'smooth' }); });
    });

    main.replaceChildren(form);
    updateSSL();
  }

  // -------------------------------------------------------------- settings

  async function pageSettings(main) {
    const s = await api('GET', '/api/settings');
    const err = h('div');
    const secretInput = (isSet) => h('input', { type: 'password', autocomplete: 'new-password', placeholder: isSet ? t('settings.secret_keep') : '' });
    const text = (v, ph) => h('input', { type: 'text', value: v || '', placeholder: ph || '', spellcheck: 'false' });
    const pem = (v) => h('textarea', { spellcheck: 'false', placeholder: '-----BEGIN CERTIFICATE-----' }, v || '');

    const f = {
      piholeUrl: text(s.piholeUrl, 'https://pi.hole'),
      piholePassword: secretInput(s.piholePasswordSet),
      piholeCaPem: pem(s.piholeCaPem),
      npmUrl: text(s.npmUrl, 'https://npm.home.lan:81'),
      npmEmail: text(s.npmEmail, 'api@home.lan'),
      npmPassword: secretInput(s.npmPasswordSet),
      npmCaPem: pem(s.npmCaPem),
      npmTargetIp: text(s.npmTargetIp, '192.168.1.5'),
      allowedDomains: text(s.allowedDomains, 'home.lan'),
      oidcEnabled: h('input', { type: 'checkbox', checked: s.oidcEnabled }),
      oidcIssuer: text(s.oidcIssuer, 'https://auth.home.lan/application/o/proxydns/'),
      oidcClientId: text(s.oidcClientId),
      oidcClientSecret: secretInput(s.oidcClientSecretSet),
      oidcRedirectUrl: text(s.oidcRedirectUrl || location.origin + '/api/auth/oidc/callback'),
      oidcButtonLabel: text(s.oidcButtonLabel, t('login.oidc')),
    };
    const setBadge = (isSet) => h('span', { class: 'badge ' + (isSet ? 'ok' : 'warn'), text: t(isSet ? 'settings.secret_set' : 'settings.secret_unset') });

    function testButton(target) {
      const out = h('span', { class: 'small' });
      const b = h('button', { type: 'button', class: 'small', text: t('settings.test') });
      b.addEventListener('click', async () => {
        b.disabled = true; out.replaceChildren(h('span', { class: 'muted', text: '…' }));
        try {
          const r = await api('POST', '/api/settings/test/' + target);
          out.replaceChildren(h('span', { class: 'badge ok', text: t('settings.test_ok') + (r.count !== undefined ? ' – ' + t('settings.test_count', { n: r.count }) : '') }));
        } catch (e) {
          out.replaceChildren(h('span', { class: 'badge err', text: errText(e) }));
        } finally { b.disabled = false; }
      });
      return h('div', { class: 'row' }, b, out, h('span', { class: 'muted small', text: t('settings.test_hint') }));
    }

    // per-backend result of the connection check that runs on save
    const checkBox = { pihole: h('div'), npm: h('div') };
    const fieldLabel = {
      piholeUrl: 'settings.url', piholePassword: 'settings.pihole_password', npmUrl: 'settings.url',
      npmEmail: 'settings.npm_email', npmPassword: 'common.password', npmTargetIp: 'settings.target_ip',
    };
    function showChecks(checks) {
      for (const [backend, box] of Object.entries(checkBox)) {
        const c = checks && checks[backend];
        if (!c) { box.replaceChildren(); continue; }
        const text = c.code === 'required_missing'
          ? t('err.required_missing') + ': ' + c.fields.map((k) => t(fieldLabel[k] || k)).join(', ')
          : errText({ code: c.code, detail: c.detail });
        box.replaceChildren(alertBox('err', text));
        for (const k of c.fields) if (f[k]) f[k].setAttribute('aria-invalid', 'true');
      }
    }

    const btn = h('button', { class: 'primary', type: 'submit', text: t('common.save') });
    const form = h('form', {},
      h('h1', { text: t('settings.title') }),
      S.configured ? null : alertBox('info', t('settings.setup_required')),
      reqNote(),
      err,
      group('Pi-hole v6',
        checkBox.pihole,
        reqField('settings.url', f.piholeUrl, 'settings.pihole_url_hint'),
        h('label', { class: 'field' }, h('span', {}, t('settings.pihole_password'), reqMark(), ' ', setBadge(s.piholePasswordSet)), f.piholePassword, h('small', { text: t('settings.pihole_password_hint') })),
        field('settings.ca_pem', f.piholeCaPem, 'settings.ca_pem_hint_pihole'),
        testButton('pihole')),
      group('Nginx Proxy Manager',
        checkBox.npm,
        reqField('settings.url', f.npmUrl, 'settings.npm_url_hint'),
        reqField('settings.npm_email', f.npmEmail, 'settings.npm_email_hint'),
        h('label', { class: 'field' }, h('span', {}, t('common.password'), reqMark(), ' ', setBadge(s.npmPasswordSet)), f.npmPassword),
        field('settings.ca_pem', f.npmCaPem, 'settings.ca_pem_hint'),
        reqField('settings.target_ip', f.npmTargetIp, 'settings.target_ip_hint'),
        testButton('npm')),
      group(t('settings.section_security'),
        field('settings.allowed_domains', f.allowedDomains, 'settings.allowed_domains_hint')),
      s.oidcAvailable ? group('OIDC / SSO',
        switchField('settings.oidc_enabled', f.oidcEnabled),
        field('settings.oidc_issuer', f.oidcIssuer),
        h('div', { class: 'grid2' },
          field('settings.oidc_client_id', f.oidcClientId),
          h('label', { class: 'field' }, h('span', {}, t('settings.oidc_client_secret') + ' ', setBadge(s.oidcClientSecretSet)), f.oidcClientSecret)),
        field('settings.oidc_redirect', f.oidcRedirectUrl, 'settings.oidc_redirect_hint'),
        field('settings.oidc_label', f.oidcButtonLabel),
        alertBox('info', t('settings.oidc_mapping')),
        testButton('oidc')) : null,
      h('div', { class: 'row end' }, btn));

    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const secret = (el) => (el.value ? el.value : undefined);
      const body = {
        piholeUrl: f.piholeUrl.value, piholePassword: secret(f.piholePassword), piholeCaPem: f.piholeCaPem.value,
        npmUrl: f.npmUrl.value, npmEmail: f.npmEmail.value, npmPassword: secret(f.npmPassword), npmCaPem: f.npmCaPem.value,
        npmTargetIp: f.npmTargetIp.value, allowedDomains: f.allowedDomains.value,
        oidcEnabled: f.oidcEnabled.checked, oidcIssuer: f.oidcIssuer.value, oidcClientId: f.oidcClientId.value,
        oidcClientSecret: secret(f.oidcClientSecret), oidcRedirectUrl: f.oidcRedirectUrl.value, oidcButtonLabel: f.oidcButtonLabel.value,
      };
      for (const el of Object.values(f)) el.removeAttribute('aria-invalid');
      showChecks(null);
      btn.textContent = t('settings.checking');
      busy(btn, err, async () => {
        let res;
        try {
          res = await api('PUT', '/api/settings', body);
        } catch (e) {
          btn.textContent = t('common.save');
          if (e.detail && f[e.detail]) { f[e.detail].setAttribute('aria-invalid', 'true'); f[e.detail].focus(); e.detail = undefined; }
          if (e.code === 'settings_check_failed' && e.data) showChecks(e.data.checks);
          throw e;
        }
        const wasConfigured = S.configured;
        S.configured = !!(res && res.configured);
        toast(t(!wasConfigured && S.configured ? 'settings.setup_complete' : 'settings.saved'));
        render();
      }).then(() => { if (err.childElementCount) err.scrollIntoView({ behavior: 'smooth' }); });
    });
    main.replaceChildren(form);
  }

  // ------------------------------------------------------------------ users

  async function pageUsers(main) {
    const users = await api('GET', '/api/users');
    const err = h('div');
    const desktop = S.info.mode === 'desktop';
    const tbody = h('tbody');

    async function update(u, body, msg) {
      await api('PUT', '/api/users/' + u.id, body);
      toast(msg || t('common.saved'));
      render();
    }

    function editRow(u, tr) {
      const email = h('input', { type: 'email', value: u.email });
      const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: t('users.password_keep') });
      const rerr = h('div');
      const save = h('button', { type: 'button', class: 'primary small', text: t('common.save') });
      save.addEventListener('click', () => busy(save, rerr, () => update(u, { email: email.value.trim(), password: pw.value || undefined })));
      const row = h('tr', { class: 'edit-row' }, h('td', { colspan: 6 },
        rerr,
        h('div', { class: 'grid2' },
          desktop ? null : field('common.email', email, 'users.email_hint'),
          field('users.new_password', pw, 'common.password_hint')),
        h('div', { class: 'row end' },
          h('button', { type: 'button', class: 'small', text: t('common.cancel'), onclick: () => row.remove() }),
          save)));
      tr.after(row);
    }

    for (const u of users) {
      const self = u.id === S.user.id;
      const role = h('select', { disabled: self }, h('option', { value: 'user', text: t('users.role_user') }), h('option', { value: 'admin', text: t('users.role_admin') }));
      role.value = u.role;
      role.addEventListener('change', () => update(u, { role: role.value }).catch((e) => { toast(errText(e), 'err'); role.value = u.role; }));
      const badges = [];
      if (u.disabled) badges.push(h('span', { class: 'badge err', text: t('users.disabled') }));
      if (u.locked) badges.push(h('span', { class: 'badge warn', text: t('users.locked') }));
      if (u.totpEnabled) badges.push(h('span', { class: 'badge ok', text: '2FA' }));
      if (u.oidcLinked) badges.push(h('span', { class: 'badge ok', text: 'OIDC' }));
      if (!u.hasPassword) badges.push(h('span', { class: 'badge', text: t('users.no_password') }));

      const actions = [];
      const tr = h('tr', {});
      actions.push(h('button', { type: 'button', class: 'small', text: t('common.edit'), onclick: () => editRow(u, tr) }));
      if (!self) actions.push(h('button', { type: 'button', class: 'small', text: t(u.disabled ? 'users.enable' : 'users.disable'), onclick: () => update(u, { disabled: !u.disabled }).catch((e) => toast(errText(e), 'err')) }));
      if (u.locked) actions.push(h('button', { type: 'button', class: 'small', text: t('users.unlock'), onclick: () => update(u, { unlock: true }) }));
      if (u.totpEnabled) actions.push(confirmButton(t('users.reset_mfa'), t('common.confirm'), async () => { await api('POST', '/api/users/' + u.id + '/reset-mfa'); toast(t('common.saved')); render(); }, 'small'));
      if (u.oidcLinked) actions.push(confirmButton(t('users.unlink_oidc'), t('common.confirm'), async () => { await api('POST', '/api/users/' + u.id + '/unlink-oidc'); toast(t('common.saved')); render(); }, 'small'));
      if (!self) actions.push(confirmButton(t('common.delete'), t('common.confirm_delete'), async () => {
        try { await api('DELETE', '/api/users/' + u.id); toast(t('users.deleted')); render(); } catch (e) { toast(errText(e), 'err'); }
      }));
      tr.append(
        h('td', {}, h('strong', { text: u.username }), self ? h('span', { class: 'muted small', text: ' (' + t('users.you') + ')' }) : null),
        h('td', { text: u.email || '–' }),
        h('td', {}, role),
        h('td', {}, badges),
        h('td', { class: 'small muted nowrap', text: fmtTime(u.createdAt) }),
        h('td', {}, h('div', { class: 'row' }, actions)));
      tbody.append(tr);
    }

    // create form
    const nu = h('input', { type: 'text', required: true, autocomplete: 'off' });
    const ne = h('input', { type: 'email', autocomplete: 'off' });
    const np = h('input', { type: 'password', autocomplete: 'new-password' });
    const nr = h('select', {}, h('option', { value: 'user', text: t('users.role_user') }), h('option', { value: 'admin', text: t('users.role_admin') }));
    const btn = h('button', { class: 'primary', type: 'submit', text: t('users.create') });
    const form = h('form', { class: 'group' },
      h('h2', { class: 'group-title', text: t('users.new') }),
      h('div', { class: 'card' },
        err,
        h('div', { class: 'grid2' },
          field('common.username', nu, 'users.username_hint'),
          field('users.role', nr),
          field('common.password', np, desktop ? 'common.password_hint' : 'users.password_optional_hint'),
          desktop ? null : field('common.email', ne, 'users.email_hint')),
        h('div', { class: 'row end' }, btn)));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(btn, err, async () => {
        await api('POST', '/api/users', { username: nu.value.trim(), email: ne.value.trim(), password: np.value, role: nr.value });
        toast(t('users.created'));
        render();
      });
    });

    mount(main,
      h('h1', { text: t('users.title') }),
      h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['common.username', 'common.email', 'users.role', 'users.status', 'users.created_at', ''].map((k) => h('th', { text: k ? t(k) : '' })))),
        tbody))),
      form);
  }

  // ------------------------------------------------------------------ audit

  async function pageAudit(main, params) {
    const limit = 50;
    const offset = Math.max(0, parseInt(params.get('offset') || '0', 10) || 0);
    const [data, verify] = await Promise.all([
      api('GET', '/api/audit?limit=' + limit + '&offset=' + offset),
      api('GET', '/api/audit/verify'),
    ]);
    const integrity = verify.ok
      ? alertBox('ok', t('audit.integrity_ok', { n: verify.checked }))
      : alertBox('err', t('audit.integrity_broken', { id: verify.brokenAt }));
    const rows = data.entries.map((e) => h('tr', {},
      h('td', { class: 'nowrap small', text: fmtTime(e.ts) }),
      h('td', { text: e.username || '–' }),
      h('td', { class: 'mono small', text: e.ip }),
      h('td', { text: t('audit.action.' + e.action) === 'audit.action.' + e.action ? e.action : t('audit.action.' + e.action) }),
      h('td', { class: 'mono small', text: e.target }),
      h('td', {}, h('span', { class: 'badge ' + (e.success ? 'ok' : 'err'), text: t(e.success ? 'audit.success' : 'audit.failure') })),
      h('td', { class: 'mono small', text: e.details })));
    const nav = h('div', { class: 'row end' },
      h('span', { class: 'muted small', text: t('audit.range', { from: data.total ? offset + 1 : 0, to: offset + data.entries.length, total: data.total }) }),
      h('button', { type: 'button', class: 'small', disabled: offset === 0, text: '←', onclick: () => { location.hash = '#/audit?offset=' + Math.max(0, offset - limit); } }),
      h('button', { type: 'button', class: 'small', disabled: offset + limit >= data.total, text: '→', onclick: () => { location.hash = '#/audit?offset=' + (offset + limit); } }));
    mount(main,
      h('h1', { text: t('audit.title') }),
      integrity,
      h('div', { class: 'card' },
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, ['audit.time', 'common.username', 'audit.ip', 'audit.action', 'audit.target', 'audit.result', 'audit.details'].map((k) => h('th', { text: t(k) })))),
          h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 7, class: 'muted center', text: t('audit.empty') }))))),
        nav));
  }

  // ---------------------------------------------------------------- account

  async function pageAccount(main) {
    const me = await api('GET', '/api/auth/me');
    S.user = me.user;
    const u = me.user;

    // password
    const perr = h('div');
    const cur = h('input', { type: 'password', autocomplete: 'current-password' });
    const n1 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
    const n2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
    const pbtn = h('button', { class: 'primary', type: 'submit', text: t('account.change_password') });
    const pform = h('form', { class: 'group' },
      h('h2', { class: 'group-title', text: t('account.password_title') }),
      h('div', { class: 'card' },
        perr,
        u.hasPassword ? field('account.current_password', cur) : alertBox('info', t('account.no_password_yet')),
        h('div', { class: 'grid2' }, field('account.new_password', n1, 'common.password_hint'), field('account.password_repeat', n2)),
        h('div', { class: 'row end' }, pbtn)));
    pform.addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (n1.value !== n2.value) { perr.replaceChildren(alertBox('err', t('err.password_mismatch'))); return; }
      busy(pbtn, perr, async () => {
        await api('POST', '/api/account/password', { current: cur.value, new: n1.value });
        cur.value = n1.value = n2.value = '';
        toast(t('account.password_changed'));
        render();
      });
    });

    // TOTP
    const terr = h('div');
    const tinner = h('div', { class: 'card' }, terr);
    const tcard = h('section', { class: 'group' }, h('h2', { class: 'group-title', text: t('account.totp_title') }), tinner);
    if (u.totpEnabled) {
      const pw = h('input', { type: 'password', autocomplete: 'current-password' });
      const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, class: 'mono' });
      const b = h('button', { type: 'submit', class: 'danger', text: t('account.totp_disable') });
      const f = h('form', {},
        alertBox('ok', t('account.totp_active')),
        h('div', { class: 'grid2' }, u.hasPassword ? field('account.current_password', pw) : null, field('mfa.code', code)),
        h('div', { class: 'row end' }, b));
      f.addEventListener('submit', (ev) => {
        ev.preventDefault();
        busy(b, terr, async () => {
          await api('POST', '/api/account/totp/disable', { password: pw.value, code: code.value });
          toast(t('account.totp_disabled'));
          render();
        });
      });
      tinner.append(f);
    } else {
      const start = h('button', { type: 'button', class: 'primary', text: t('account.totp_setup') });
      const area = h('div');
      start.addEventListener('click', () => busy(start, terr, async () => {
        const r = await api('POST', '/api/account/totp/setup');
        const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, required: true, class: 'mono' });
        const b = h('button', { type: 'submit', class: 'primary', text: t('account.totp_enable') });
        const f = h('form', {},
          h('p', { text: t('account.totp_scan') }),
          h('img', { src: r.qr, alt: 'QR', class: 'qr' }),
          h('p', { class: 'small' }, t('account.totp_manual') + ' ', h('code', { text: r.secret })),
          field('mfa.code', code),
          h('div', { class: 'row end' }, b));
        f.addEventListener('submit', (ev) => {
          ev.preventDefault();
          busy(b, terr, async () => {
            await api('POST', '/api/account/totp/enable', { code: code.value });
            toast(t('account.totp_enabled'));
            render();
          });
        });
        start.remove();
        area.replaceChildren(f);
        code.focus();
      }));
      tinner.append(h('p', { class: 'muted', text: t('account.totp_intro') }), start, area);
    }

    mount(main,
      h('h1', { text: t('account.title') }),
      h('div', { class: 'card' },
        h('div', { class: 'row' },
          h('strong', { text: u.username }),
          h('span', { class: 'badge', text: t(u.role === 'admin' ? 'users.role_admin' : 'users.role_user') }),
          u.email ? h('span', { class: 'muted', text: u.email }) : null,
          u.oidcLinked ? h('span', { class: 'badge ok', text: 'OIDC' }) : null),
        h('p', { class: 'muted small', text: 'Version ' + S.info.version + ' · ' + t(S.info.mode === 'desktop' ? 'account.mode_desktop' : 'account.mode_server') })),
      pform,
      tcard);
  }

  // ------------------------------------------------------------------- boot

  async function boot() {
    const main = document.getElementById('app');
    try {
      await loadLang(pickLang());
      S.info = await api('GET', '/api/info');
      if (!S.info.setupRequired && S.info.mode !== 'desktop') {
        try { setSession(await api('GET', '/api/auth/me')); } catch { /* not logged in */ }
      }
    } catch (e) {
      main.replaceChildren(alertBox('err', 'Start failed: ' + (e.code || e.message)));
      return;
    }
    window.addEventListener('hashchange', render);
    render();
  }

  boot();
})();

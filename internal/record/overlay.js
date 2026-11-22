// har2mcp recorder overlay. The recorder injects this script into every
// document of the recorded tab before the page's own scripts run.
//
// It reports to the recorder through the DevTools binding __har2mcpEmit,
// one JSON string per event:
//   {type:"step_start",name}  {type:"step_end"}
//   {type:"click",text,ariaLabel,role,selector}
//   {type:"input",label,name,selector,inputType,value}
//   {type:"login_submit",usernameSelector,passwordSelector,submitSelector,username,password,pageUrl}
//   {type:"hello",url}  (a new document is ready; the recorder resends its state)
// Every event also carries t, the time in milliseconds since the epoch.
//
// In the top frame it shows a small box in the bottom-right corner where the
// user names and ends steps, and it exposes the same controls to scripts as
// window.__har2mcp.startStep(name) and window.__har2mcp.endStep().
(function () {
  'use strict';
  if (window.__har2mcpInstalled) return;
  Object.defineProperty(window, '__har2mcpInstalled', { value: true });

  // Keep our own references, in case the page replaces the globals later.
  const now = Date.now.bind(Date);
  const stringify = JSON.stringify.bind(JSON);
  const BINDING = '__har2mcpEmit';
  const isTop = window.top === window;
  const queue = [];

  function send(o) {
    const f = window[BINDING];
    if (typeof f !== 'function') return false;
    try {
      f(stringify(o));
    } catch (e) {
      // The binding throws only for a non-string argument; nothing to do.
    }
    return true;
  }
  function flushQueue() {
    while (queue.length && send(queue[0])) queue.shift();
    if (queue.length) setTimeout(flushQueue, 50);
  }
  function emit(o) {
    o.t = now();
    if (queue.length || !send(o)) {
      queue.push(o);
      if (queue.length === 1) setTimeout(flushQueue, 50);
    }
  }

  function clean(s, max) {
    s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
    return s.length > (max || 80) ? s.slice(0, max || 80) : s;
  }
  function esc(s) {
    return window.CSS && CSS.escape ? CSS.escape(s) : String(s).replace(/[^\w-]/g, (c) => '\\' + c);
  }
  function quote(s) {
    return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  function unique(root, sel, el) {
    try {
      const all = root.querySelectorAll(sel);
      return all.length === 1 && all[0] === el;
    } catch (e) {
      return false;
    }
  }

  // selectorOf builds a short CSS selector that finds el again: its id, a
  // name or data attribute, or a path of :nth-of-type steps up to an
  // ancestor with an id.
  function selectorOf(el) {
    if (!el || el.nodeType !== 1) return '';
    const root = el.getRootNode && el.getRootNode().querySelectorAll ? el.getRootNode() : document;
    const tag = el.localName;
    if (el.id && unique(root, '#' + esc(el.id), el)) return '#' + esc(el.id);
    const name = el.getAttribute('name');
    if (name) {
      const s = tag + '[name=' + quote(name) + ']';
      if (unique(root, s, el)) return s;
    }
    const cls = el.classList && el.classList.length ? '.' + esc(el.classList[0]) : '';
    for (const a of el.attributes) {
      if (!a.name.startsWith('data-') || !a.value || a.value.length > 100) continue;
      const s = (cls || tag) + '[' + a.name + '=' + quote(a.value) + ']';
      if (unique(root, s, el)) return s;
    }
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 10) {
      if (node !== el && node.id && unique(root, '#' + esc(node.id), node)) {
        parts.unshift('#' + esc(node.id));
        break;
      }
      let part = node.localName;
      const parent = node.parentElement;
      if (parent) {
        const same = Array.prototype.filter.call(parent.children, (c) => c.localName === node.localName);
        if (same.length > 1) part += ':nth-of-type(' + (same.indexOf(node) + 1) + ')';
      }
      parts.unshift(part);
      if (node.localName === 'body' || node.localName === 'html') break;
      node = parent;
    }
    return parts.join(' > ');
  }

  function roleOf(el) {
    const r = el.getAttribute('role');
    if (r) return r;
    switch (el.localName) {
      case 'button':
      case 'summary':
        return 'button';
      case 'a':
        return el.hasAttribute('href') ? 'link' : '';
      case 'select':
        return 'combobox';
      case 'textarea':
        return 'textbox';
      case 'input': {
        const t = (el.type || 'text').toLowerCase();
        if (t === 'button' || t === 'submit' || t === 'reset' || t === 'image') return 'button';
        if (t === 'checkbox' || t === 'radio') return t;
        return 'textbox';
      }
    }
    return '';
  }

  function textOf(el) {
    if (el.localName === 'input') return clean(el.value || el.getAttribute('aria-label') || el.title);
    let t = clean(el.innerText || el.textContent);
    if (!t) {
      const img = el.querySelector && el.querySelector('img[alt]');
      t = clean(el.getAttribute('title') || (img && img.alt));
    }
    return t;
  }

  function labelOf(el) {
    if (el.labels && el.labels.length) {
      const t = clean(el.labels[0].innerText || el.labels[0].textContent);
      if (t) return t;
    }
    const aria = el.getAttribute('aria-label');
    if (aria) return clean(aria);
    const by = el.getAttribute('aria-labelledby');
    if (by) {
      const t = by
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((n) => n.innerText || n.textContent)
        .join(' ');
      if (clean(t)) return clean(t);
    }
    return clean(el.getAttribute('placeholder') || el.title || '');
  }

  const TEXTLIKE = ['text', 'email', 'tel', 'number', 'search', 'url'];
  function isField(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.localName === 'select' || el.localName === 'textarea') return true;
    if (el.localName !== 'input') return false;
    const t = (el.type || 'text').toLowerCase();
    return t !== 'hidden' && t !== 'button' && t !== 'submit' && t !== 'reset' && t !== 'image';
  }
  function fieldValue(el) {
    const t = (el.type || '').toLowerCase();
    if (t === 'checkbox') return el.checked ? 'true' : 'false';
    if (t === 'radio') return el.checked ? el.value : null;
    if (t === 'file') return Array.prototype.map.call(el.files || [], (f) => f.name).join(', ');
    return el.value;
  }

  let host = null; // the overlay element, set in the top frame

  function fromOverlay(e) {
    return host !== null && (e.target === host || (e.composedPath && e.composedPath().indexOf(host) >= 0));
  }
  function realTarget(e) {
    const p = e.composedPath ? e.composedPath() : [];
    return p.length && p[0].nodeType === 1 ? p[0] : e.target;
  }

  // Typed values: reported on change, and also flushed before a click, a
  // submit, an Enter key or the end of a step, so a value typed just before
  // pressing Enter is not lost.
  const lastSent = new WeakMap();
  const pending = new Set();
  function reportField(el) {
    pending.delete(el);
    const v = fieldValue(el);
    if (v === null || lastSent.get(el) === v) return;
    if (v === '' && !lastSent.has(el)) return;
    lastSent.set(el, v);
    emit({
      type: 'input',
      label: labelOf(el),
      name: el.getAttribute('name') || '',
      selector: selectorOf(el),
      inputType: el.localName === 'input' ? (el.type || 'text').toLowerCase() : el.localName,
      value: String(v),
    });
  }
  function flushFields() {
    Array.from(pending).forEach(reportField);
  }

  // Login capture: a form (or page) with exactly one filled password field.
  let pwDirty = false;
  let lastLogin = { key: '', t: 0 };
  function loginParts(scope) {
    const pws = Array.prototype.filter.call(scope.querySelectorAll('input[type=password]'), (i) => i.value);
    if (pws.length !== 1) return null;
    const pw = pws[0];
    const users = Array.prototype.filter.call(
      (pw.form || scope).querySelectorAll('input'),
      (i) =>
        TEXTLIKE.indexOf((i.type || 'text').toLowerCase()) >= 0 &&
        i.value &&
        i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    return { pw: pw, user: users.length ? users[users.length - 1] : null };
  }
  function emitLogin(parts, submit) {
    const key = (parts.user ? parts.user.value : '') + '\u0000' + parts.pw.value;
    const t = now();
    if (key === lastLogin.key && t - lastLogin.t < 1500) return;
    lastLogin = { key: key, t: t };
    pwDirty = false;
    emit({
      type: 'login_submit',
      usernameSelector: parts.user ? selectorOf(parts.user) : '',
      passwordSelector: selectorOf(parts.pw),
      submitSelector: submit ? selectorOf(submit) : '',
      username: parts.user ? parts.user.value : '',
      password: parts.pw.value,
      pageUrl: location.href,
    });
  }

  const CLICKABLE =
    'button,a[href],input,select,textarea,label,summary,[role=button],[role=link],[role=menuitem],' +
    '[role=tab],[role=option],[role=checkbox],[role=switch],[role=radio],[onclick],[tabindex]';

  addEventListener(
    'click',
    (e) => {
      if (fromOverlay(e) || !e.isTrusted) return;
      flushFields();
      const target = realTarget(e);
      const el = (target.closest && target.closest(CLICKABLE)) || target;
      if (el.nodeType !== 1) return;
      const t = (el.type || '').toLowerCase();
      if (el.localName === 'textarea' || el.localName === 'select') return;
      if (el.localName === 'input' && (TEXTLIKE.indexOf(t) >= 0 || t === 'password' || t === '')) return;
      emit({
        type: 'click',
        text: textOf(el),
        ariaLabel: clean(el.getAttribute('aria-label')),
        role: roleOf(el),
        selector: selectorOf(el),
      });
      // A login button outside any form: the password field was just typed in.
      if (pwDirty && roleOf(el) === 'button' && !el.form) {
        const parts = loginParts(document);
        if (parts && !parts.pw.form) emitLogin(parts, el);
      }
    },
    true
  );

  addEventListener(
    'input',
    (e) => {
      if (fromOverlay(e)) return;
      const el = realTarget(e);
      if (!isField(el)) return;
      pending.add(el);
      if ((el.type || '').toLowerCase() === 'password') pwDirty = true;
    },
    true
  );

  addEventListener(
    'change',
    (e) => {
      if (fromOverlay(e)) return;
      const el = realTarget(e);
      if (isField(el)) reportField(el);
    },
    true
  );

  addEventListener(
    'submit',
    (e) => {
      if (fromOverlay(e)) return;
      flushFields();
      const form = e.target;
      if (!form || form.localName !== 'form') return;
      const parts = loginParts(form);
      if (parts) emitLogin(parts, e.submitter || form.querySelector('[type=submit],button:not([type])'));
    },
    true
  );

  addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Enter' || fromOverlay(e)) return;
      flushFields();
      const el = realTarget(e);
      // Enter in a field outside a form submits nothing by itself; if it is
      // a login field, the page's own key handler logs in.
      if (isField(el) && !el.form && pwDirty) {
        const parts = loginParts(document);
        if (parts && !parts.pw.form) emitLogin(parts, null);
      }
    },
    true
  );

  if (!isTop) return;

  // ---- the box in the top frame ----

  const state = { step: null, count: 0, steps: 0 };
  let ui = null;

  function startStep(name) {
    flushFields();
    name = clean(name, 200);
    emit({ type: 'step_start', name: name });
    state.step = name;
    state.count = 0;
    state.steps++;
    render();
  }
  function endStep() {
    if (state.step === null) return;
    flushFields();
    emit({ type: 'step_end' });
    state.step = null;
    render();
  }
  function sync(s) {
    if (!s || typeof s !== 'object') return;
    state.step = typeof s.step === 'string' ? s.step : null;
    state.count = s.count | 0;
    state.steps = s.steps | 0;
    render();
  }

  Object.defineProperty(window, '__har2mcp', {
    value: Object.freeze({ startStep: startStep, endStep: endStep, _sync: sync, version: 1 }),
  });

  const CSS_TEXT = [
    ':host{all:initial}',
    '.box{position:fixed;right:16px;bottom:16px;z-index:2147483647;width:264px;box-sizing:border-box;',
    'background:#0f1716;color:#e6f2ef;border:1px solid #2dd4bf;border-radius:10px;',
    'box-shadow:0 8px 28px rgba(0,0,0,.45);font:13px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}',
    '.head{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-bottom:1px solid #22302d}',
    '.brand{font:700 12px/1 ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace;color:#2dd4bf;letter-spacing:.02em}',
    '.body{padding:8px 10px 10px;display:grid;gap:7px}',
    '.line{display:flex;align-items:center;gap:8px}',
    'label{color:#9fb6b0}',
    'input{flex:1;min-width:0;box-sizing:border-box;padding:5px 7px;border:1px solid #2b3b37;border-radius:6px;',
    'background:#091110;color:#e6f2ef;font:inherit}',
    'input:disabled{color:#2dd4bf;border-color:#1d2a27}',
    'button{all:unset;cursor:pointer;box-sizing:border-box;padding:4px 12px;border-radius:6px;font-weight:600;',
    'background:#2dd4bf;color:#04201b}',
    'button:focus-visible{outline:2px solid #e6f2ef;outline-offset:2px}',
    'button.min{background:transparent;color:#9fb6b0;padding:0 4px;font-size:15px;line-height:1}',
    '.dot{width:9px;height:9px;border-radius:50%;background:#f87171;flex:none}',
    '.rec .dot{animation:pulse 1.4s infinite}',
    '@keyframes pulse{50%{opacity:.35}}',
    '.state{flex:1;color:#9fb6b0}',
    '.count{color:#9fb6b0;font-size:12px}',
    '.hint{color:#facc15}',
    '.pill{position:fixed;right:16px;bottom:16px;z-index:2147483647;display:flex;gap:6px;align-items:center;',
    'padding:5px 10px;border-radius:999px;background:#0f1716;color:#2dd4bf;border:1px solid #2dd4bf;',
    'font:700 12px/1 ui-monospace,Menlo,Consolas,monospace}',
    '[hidden]{display:none!important}',
  ].join('');

  function el(tag, props, kids) {
    const n = document.createElement(tag);
    for (const k in props || {}) {
      if (k === 'text') n.textContent = props[k];
      else n.setAttribute(k, props[k]);
    }
    (kids || []).forEach((c) => n.append(c));
    return n;
  }

  function mount() {
    if (host && host.isConnected && host.ownerDocument === document) return;
    const parent = document.documentElement;
    if (!parent) return;
    host = document.createElement('har2mcp-overlay');
    host.setAttribute('style', 'all:initial');
    const root = host.attachShadow({ mode: 'open' });
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS_TEXT);
      root.adoptedStyleSheets = [sheet];
    } catch (e) {
      root.append(el('style', { text: CSS_TEXT }));
    }
    const name = el('input', { class: 'name', placeholder: 'e.g. list disks', maxlength: '200', 'aria-label': 'Step name' });
    const go = el('button', { class: 'go', type: 'button', text: 'Start' });
    const min = el('button', { class: 'min', type: 'button', title: 'Minimize', 'aria-label': 'Minimize', text: '–' });
    const stateText = el('span', { class: 'state', text: 'Recording' });
    const count = el('div', { class: 'count', 'aria-live': 'polite' });
    const box = el('div', { class: 'box rec', role: 'region', 'aria-label': 'har2mcp recorder' }, [
      el('div', { class: 'head' }, [el('span', { class: 'brand', text: 'har2mcp' }), min]),
      el('div', { class: 'body' }, [
        el('div', { class: 'line' }, [el('label', { text: 'Step:' }), name]),
        el('div', { class: 'line' }, [el('span', { class: 'dot' }), stateText, go]),
        count,
      ]),
    ]);
    const pill = el('button', { class: 'pill', type: 'button', title: 'Show the har2mcp recorder', hidden: '' }, [
      el('span', { class: 'dot' }),
      document.createTextNode('har2mcp'),
    ]);
    root.append(box, pill);
    // Keys typed in the box must not reach the page's shortcuts.
    ['keydown', 'keyup', 'keypress'].forEach((t) => root.addEventListener(t, (e) => e.stopPropagation()));
    name.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') toggle();
    });
    go.addEventListener('click', toggle);
    min.addEventListener('click', () => {
      box.hidden = true;
      pill.hidden = false;
    });
    pill.addEventListener('click', () => {
      pill.hidden = true;
      box.hidden = false;
    });
    function toggle() {
      if (state.step !== null) {
        endStep();
        name.value = '';
        name.focus();
        return;
      }
      if (!clean(name.value)) {
        count.textContent = 'Type a name for this step first.';
        count.className = 'count hint';
        name.focus();
        return;
      }
      startStep(name.value);
    }
    ui = { name: name, go: go, count: count, stateText: stateText };
    parent.append(host);
    render();
  }

  function render() {
    if (!ui) return;
    const active = state.step !== null;
    ui.go.textContent = active ? 'Done' : 'Start';
    ui.name.disabled = active;
    if (active) ui.name.value = state.step;
    ui.stateText.textContent = active ? 'Recording step' : 'Recording';
    ui.count.className = 'count';
    if (active) ui.count.textContent = state.count + (state.count === 1 ? ' request' : ' requests') + ' this step';
    else if (state.steps) ui.count.textContent = state.steps + (state.steps === 1 ? ' step' : ' steps') + ' recorded. Name the next one.';
    else ui.count.textContent = 'Name a step, then press Start.';
  }

  function ready() {
    mount();
    emit({ type: 'hello', url: location.href });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready, { once: true });
  else ready();
  // Some pages replace the whole document; put the box back.
  setInterval(mount, 1000);
})();

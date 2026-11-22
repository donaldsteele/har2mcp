// FakeNAS SPA. Every button sends exactly one API request and nothing
// refreshes by itself afterwards, so each labeled recorder step maps to one
// operation. After login the page polls getsysinfo every 5000 ms into the
// status bar, which gives a recording unlabeled background traffic.
'use strict';
(function () {
  const $ = (s) => document.querySelector(s);
  const out = $('#out');
  const scramble = document.documentElement.dataset.scramble === '1';
  let token = '';
  let poll = 0;
  let seq = 0;

  // show puts a result in #out. data-seq counts results and data-ok tells
  // whether the last one succeeded, so scripts can wait for a click's result.
  function show(obj, ok) {
    out.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    out.dataset.ok = ok ? 'true' : 'false';
    out.dataset.seq = String(++seq);
  }

  async function call(url, opts) {
    let res;
    try {
      res = await fetch(url, opts || {});
    } catch (e) {
      return { status: 0, data: { ok: false, error: String(e) } };
    }
    let data;
    try {
      data = await res.json();
    } catch (e) {
      data = { ok: false, error: 'bad response (' + res.status + ')' };
    }
    if (res.status === 401 && url !== '/api/login') loggedOut();
    return { status: res.status, data: data };
  }

  function api(act, extra) {
    return call('/api.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Csrf-Token': token },
      body: JSON.stringify(Object.assign({ act: act }, extra || {})),
    });
  }

  function good(r) {
    return r.status === 200 && r.data && r.data.ok === true;
  }

  async function run(p) {
    const r = await p;
    show(r.data, good(r));
    return r;
  }

  function loggedIn() {
    $('#login-view').hidden = true;
    $('#app-view').hidden = false;
    clearInterval(poll);
    poll = setInterval(pollSysinfo, 5000);
  }

  function loggedOut() {
    clearInterval(poll);
    poll = 0;
    token = '';
    $('#status').textContent = 'signed out';
    $('#app-view').hidden = true;
    $('#login-view').hidden = false;
  }

  async function pollSysinfo() {
    const r = await api('getsysinfo');
    if (good(r)) {
      const d = r.data.data;
      $('#status').textContent = d.model + ' · ' + d.version + ' · up ' + d.uptime_s + 's';
    }
  }

  // sha256hex is a plain SHA-256, so Scramble works without crypto.subtle,
  // which browsers only offer on secure origins.
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  function ror(x, n) {
    return (x >>> n) | (x << (32 - n));
  }
  function sha256hex(str) {
    const bytes = new TextEncoder().encode(str);
    const n = bytes.length;
    const size = Math.ceil((n + 9) / 64) * 64;
    const m = new Uint8Array(size);
    m.set(bytes);
    m[n] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(size - 8, Math.floor((n * 8) / 0x100000000));
    dv.setUint32(size - 4, (n * 8) >>> 0);
    const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const w = new Uint32Array(64);
    for (let off = 0; off < size; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        const t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        hh = g;
        g = f;
        f = e;
        e = (d + t1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) >>> 0;
      }
      const v = [a, b, c, d, e, f, g, hh];
      for (let i = 0; i < 8; i++) h[i] = (h[i] + v[i]) >>> 0;
    }
    return h.map((x) => x.toString(16).padStart(8, '0')).join('');
  }
  window.fakenasSHA256 = sha256hex; // for tests

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('#username').value;
    let password = $('#password').value;
    if (scramble) {
      const n = await call('/api/nonce');
      if (n.status !== 200) {
        show(n.data, false);
        return;
      }
      password = sha256hex(password + ':' + n.data.nonce);
    }
    const r = await call('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password }),
    });
    if (good(r)) {
      token = r.data.data.token;
      loggedIn();
    }
    show(r.data, good(r));
  });

  $('#btn-disks').addEventListener('click', () => run(api('getdisklist')));
  $('#btn-sysinfo').addEventListener('click', () => run(api('getsysinfo')));
  $('#btn-reboot').addEventListener('click', () => run(api('reboot')));

  function addShareItem(name) {
    const list = $('#share-list');
    for (const li of list.children) {
      if (li.dataset.name === name) return;
    }
    const li = document.createElement('li');
    li.dataset.name = name;
    const label = document.createElement('span');
    label.textContent = name;
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'del-share';
    del.dataset.name = name;
    del.textContent = 'Delete';
    li.append(label, del);
    list.append(li);
  }

  $('#btn-shares').addEventListener('click', async () => {
    const r = await run(api('getsharelist'));
    if (good(r)) {
      $('#share-list').replaceChildren();
      r.data.data.forEach(addShareItem);
    }
  });

  $('#btn-add-share').addEventListener('click', async () => {
    const input = $('#share-name');
    const name = input.value.trim();
    const r = await run(api('addshare', { name: name }));
    if (good(r)) {
      addShareItem(name);
      input.value = '';
    }
  });

  $('#share-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('.del-share[data-name]');
    if (!btn) return;
    const name = btn.dataset.name;
    const r = await run(api('delshare', { name: name }));
    if (good(r)) btn.closest('li').remove();
  });

  $('#btn-upload').addEventListener('click', async () => {
    const file = $('#upload-file').files[0];
    if (!file) {
      show({ ok: false, error: 'choose a file first' }, false);
      return;
    }
    const folder = $('#upload-path').value.trim() || '/';
    const fd = new FormData();
    fd.append('path', folder);
    fd.append('file', file);
    const r = await run(call('/api/upload', { method: 'POST', headers: { 'X-Csrf-Token': token }, body: fd }));
    if (good(r)) {
      const path = folder.replace(/\/+$/, '') + '/' + file.name;
      const list = $('#file-list');
      if (!list.querySelector('a.download[data-path="' + CSS.escape(path) + '"]')) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = '#';
        a.className = 'download';
        a.dataset.path = path;
        a.textContent = path;
        li.append(a);
        list.append(li);
      }
    }
  });

  // A download link fetches the file with the CSRF header and reports its
  // size; the fake does not save it anywhere.
  $('#file-list').addEventListener('click', async (e) => {
    const a = e.target.closest('a.download[data-path]');
    if (!a) return;
    e.preventDefault();
    const path = a.dataset.path;
    let res;
    try {
      res = await fetch('/api/download?path=' + encodeURIComponent(path), { headers: { 'X-Csrf-Token': token } });
    } catch (err) {
      show({ ok: false, error: String(err) }, false);
      return;
    }
    if (res.status !== 200) {
      if (res.status === 401) loggedOut();
      const data = await res.json().catch(() => ({ ok: false, error: 'download failed (' + res.status + ')' }));
      show(data, false);
      return;
    }
    // arrayBuffer, not blob: Chrome drains a blob response without passing
    // the bytes through DevTools, so a recording would lose the body.
    const buf = await res.arrayBuffer();
    show({ ok: true, downloaded: path, bytes: buf.byteLength }, true);
  });
})();

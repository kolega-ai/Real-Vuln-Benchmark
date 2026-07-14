/* RealVuln version switcher.
   Turns the static "v1.0" tag in the brand (.brand .v) into a dropdown driven
   by /versions.json, so visitors can jump to any frozen release. Degrades
   silently: if versions.json is missing or there is only one release, the
   static label is left untouched. Loaded on every public page. */
(function () {
  var el = document.querySelector('.brand .v');
  if (!el) return;

  // resolve versions.json from the site root regardless of page depth
  // (root pages and /v/<x>/ snapshots both reach the canonical root file)
  var base = location.pathname.indexOf('/v/') === 0 ? '/' : '';
  fetch(base + 'versions.json', { cache: 'no-cache' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data || !data.versions || data.versions.length === 0) return;
      var latest = data.latest || data.versions[0].version;
      // label reflects the version this page actually represents
      var here = (location.pathname.match(/\/v\/([^/]+)\//) || [])[1] || latest;
      render(el, data.versions, latest, here);
    })
    .catch(function () {});

  function render(node, versions, latest, here) {
    node.textContent = '';
    node.style.position = 'relative';
    node.style.cursor = 'pointer';
    node.style.userSelect = 'none';

    var btn = document.createElement('span');
    btn.textContent = 'v' + here + ' ▾';
    btn.setAttribute('role', 'button');
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');
    node.appendChild(btn);

    var menu = document.createElement('div');
    menu.style.cssText =
      'position:absolute;top:140%;left:0;min-width:180px;z-index:50;' +
      'background:#16141c;border:1px solid #333;border-radius:8px;padding:4px;' +
      'box-shadow:0 8px 24px rgba(0,0,0,.5);display:none;font-weight:400';
    versions.forEach(function (v) {
      var a = document.createElement('a');
      var isLatest = v.version === latest;
      a.href = isLatest ? '/' : v.url;
      a.style.cssText =
        'display:flex;justify-content:space-between;gap:12px;align-items:baseline;' +
        'padding:7px 10px;border-radius:6px;text-decoration:none;color:#e6e1d6;' +
        'font-size:13px;white-space:nowrap';
      a.onmouseenter = function () { a.style.background = '#23202b'; };
      a.onmouseleave = function () { a.style.background = 'transparent'; };
      var left = document.createElement('span');
      left.textContent = 'v' + v.version;
      if (v.version === here) { left.style.color = '#cfa45c'; left.style.fontWeight = '600'; }
      var right = document.createElement('span');
      right.style.cssText = 'font-size:11px;color:#8c8478';
      right.textContent = (isLatest ? 'latest' : (v.release_date || '')) +
        (v.repos ? ' · ' + v.repos + ' repos' : '');
      a.appendChild(left); a.appendChild(right);
      menu.appendChild(a);
    });
    node.appendChild(menu);

    function close() {
      menu.style.display = 'none';
      btn.setAttribute('aria-expanded', 'false');
      document.removeEventListener('click', onDoc);
    }
    function onDoc(e) { if (!node.contains(e.target)) close(); }
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      var open = menu.style.display === 'block';
      if (open) { close(); return; }
      menu.style.display = 'block';
      btn.setAttribute('aria-expanded', 'true');
      setTimeout(function () { document.addEventListener('click', onDoc); }, 0);
    });
  }
})();

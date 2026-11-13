(function () {
  'use strict';
  var api = window.REALVULN_PRIVATE_SCORE_API;
  var launchReceipts = [];
  var officialScanner = 'kolega-python-large-official';
  function el(id) { return document.getElementById(id); }
  function status(id, message) { el(id).textContent = message; }
  function validId(value) { return /^[0-9a-f]{32}$/.test(value); }
  function cell(row, value) { var td = document.createElement('td'); td.textContent = String(value); row.appendChild(td); }
  function percent(value) { return (Number(value) * 100).toFixed(2) + '%'; }
  function renderRepoScores(receipt) {
    var body = el('repo-scores'); body.replaceChildren();
    var scores = receipt && receipt.repo_scores;
    if (!scores) { status('repo-status', 'Repository breakdown is unavailable for this receipt.'); return; }
    var names = { sentry: 'Sentry', odoo: 'Odoo', netbox: 'NetBox', airflow: 'Airflow', saleor: 'Saleor' };
    ['sentry', 'odoo', 'netbox', 'airflow', 'saleor'].forEach(function (repo) {
      if (!scores[repo]) return;
      var r = scores[repo], row = document.createElement('tr');
      cell(row, names[repo]); cell(row, percent(r.f3)); cell(row, percent(r.recall));
      cell(row, r.tp); cell(row, r.fp); cell(row, r.fn); body.appendChild(row);
    });
    status('repo-status', body.children.length + ' pinned repositories · ' + receipt.gt + ' scored ground-truth rows in total.');
  }
  function renderFeatured(receipt) {
    if (!receipt) {
      status('featured-score', 'No score yet'); status('featured-detail', '');
      status('repo-status', 'Repository breakdown is unavailable.');
      el('repo-scores').replaceChildren();
      return;
    }
    status('featured-score', percent(receipt.f3));
    status('featured-detail', receipt.scanner + ' · ' + receipt.tp + ' matches · ' + receipt.fp + ' unmatched · ' + receipt.fn + ' misses');
    renderRepoScores(receipt);
  }
  var navToggle = document.querySelector('.nav-toggle'), navMenu = el('mobile-menu');
  if (navToggle && navMenu) navToggle.addEventListener('click', function () {
    var open = navMenu.classList.toggle('open');
    navToggle.textContent = open ? '✕' : '≡';
  });
  async function get(path) {
    var res = await fetch(api + path, { cache: 'no-store' });
    if (!res.ok) throw new Error('Request failed (' + res.status + ')');
    return res.json();
  }
  async function loadLaunch() {
    try {
      var response = await fetch('private-score-launch.json', { cache: 'no-store' });
      if (!response.ok) throw new Error('No launch receipt');
      var data = await response.json();
      launchReceipts = Array.isArray(data) ? data : [data];
      renderFeatured(launchReceipts.find(function (r) { return r.scanner === officialScanner; }));
    } catch (_) { renderFeatured(null); }
  }
  async function refresh() {
    try {
      var result = api ? await get('/leaderboard') : { receipts: launchReceipts };
      var receipts = result.receipts.slice().sort(function (a, b) { return b.f3 - a.f3; });
      var body = el('private-leaderboard'); body.replaceChildren();
      receipts.forEach(function (r) {
        var row = document.createElement('tr');
        cell(row, r.scanner); cell(row, percent(r.f3)); cell(row, percent(r.recall));
        cell(row, r.tp); cell(row, r.fp); cell(row, r.fn);
        var td = document.createElement('td');
        if (api) {
          var a = document.createElement('a');
          a.href = 'private-scores.html?receipt=' + encodeURIComponent(r.run_id);
          a.textContent = r.run_id.slice(0, 8); td.appendChild(a);
        } else td.textContent = r.run_id.slice(0, 8);
        row.appendChild(td); body.appendChild(row);
      });
      if (!launchReceipts.length) renderFeatured(receipts.find(function (r) { return r.scanner === officialScanner; }));
      status('leaderboard-status', api
        ? (receipts.length ? receipts.length + ' published receipt(s)' : 'No published receipts yet.')
        : 'Published score preview. Live receipts are unavailable.');
    } catch (_) { status('leaderboard-status', api ? 'Could not load private scores.' : 'The private scoring endpoint has not been configured.'); }
  }
  el('lookup-button').addEventListener('click', async function () {
    var id = el('receipt-id').value.trim();
    if (!api || !validId(id)) { status('lookup-status', 'Enter a valid receipt ID.'); return; }
    try {
      var r = await get('/receipts/' + id);
      status('lookup-status', r.scanner + ': F3 ' + percent(r.f3) + ', ' + r.tp + ' matches, ' + r.fp + ' unmatched, ' + r.fn + ' misses. ' + (r.published ? 'Published.' : 'Unpublished.'));
    } catch (_) { status('lookup-status', 'Receipt not found or access denied.'); }
  });
  el('publish-button').addEventListener('click', async function () {
    var id = el('publish-id').value.trim(), token = el('publish-token').value;
    if (!api || !validId(id) || !token) { status('publish-status', 'Enter a valid receipt ID and token.'); return; }
    try {
      var res = await fetch(api + '/publish', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({run_id:id,publish_token:token}),cache:'no-store'});
      if (!res.ok) throw new Error();
      el('publish-token').value = '';
      status('publish-status', 'Receipt published.'); refresh();
    } catch (_) { status('publish-status', 'Publication failed. Check the receipt and token.'); }
  });
  var linked = new URLSearchParams(location.search).get('receipt');
  if (linked && validId(linked)) el('receipt-id').value = linked;
  if (!api) {
    el('lookup-button').disabled = true;
    el('publish-button').disabled = true;
    status('lookup-status', 'Receipt lookup opens when the production API is configured.');
    status('publish-status', 'External submissions are not open yet.');
  }
  loadLaunch().then(refresh);
}());

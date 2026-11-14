(function () {
  'use strict';
  var api = window.REALVULN_PRIVATE_SCORE_API;
  var names = {
    'kolega-python-large-official': 'Kolega DevSec Max',
    'gpt-daybreak-blue-codex-cli': 'Daybreak Blue',
    'deepseek-v4.1-flash-agentic-v1': 'DeepSeek V4.1 Flash',
    'claude-sonnet-5-cc-agentic-v1': 'Sonnet 5'
  };
  var snapshot = [];
  function el(id) { return document.getElementById(id); }
  function validId(value) { return /^[0-9a-f]{32}$/.test(value); }
  function percent(value) { return (Number(value) * 100).toFixed(2) + '%'; }
  function show(receipt) {
    el('result-title').textContent = names[receipt.scanner] || receipt.scanner;
    el('result-f3').textContent = percent(receipt.f3) + ' F3';
    el('result-detail').textContent = percent(receipt.recall) + ' recall · ' + Number(receipt.tp).toLocaleString() + ' matches · ' + Number(receipt.fp).toLocaleString() + ' unmatched · ' + Number(receipt.fn).toLocaleString() + ' misses';
    el('result-state').textContent = receipt.published ? 'Published receipt.' : 'Unpublished receipt · visible by ID only.';
    el('receipt-result').hidden = false;
    el('lookup-status').textContent = '';
  }
  var navToggle = document.querySelector('.nav-toggle'), navMenu = el('mobile-menu');
  if (navToggle && navMenu) navToggle.addEventListener('click', function () {
    var open = navMenu.classList.toggle('open');
    navToggle.textContent = open ? '✕' : '≡';
  });
  async function loadSnapshot() {
    try {
      var response = await fetch('private-score-launch.json', { cache: 'no-store' });
      if (response.ok) {
        var data = await response.json();
        snapshot = Array.isArray(data) ? data : [data];
      }
    } catch (_) { /* Live receipt lookup remains available. */ }
  }
  async function lookup(id) {
    el('receipt-result').hidden = true;
    if (!validId(id)) { el('lookup-status').textContent = 'Enter a valid 32-character receipt ID.'; return; }
    var local = snapshot.find(function (receipt) { return receipt.run_id === id; });
    if (local) { show(local); return; }
    if (api) {
      try {
        var response = await fetch(api + '/receipts/' + id, { cache: 'no-store' });
        if (response.ok) { show(await response.json()); return; }
      } catch (_) { /* Local preview may not be permitted by production CORS. */ }
    }
    el('lookup-status').textContent = 'Receipt not found or live lookup is unavailable.';
  }
  el('lookup-form').addEventListener('submit', function (event) {
    event.preventDefault();
    lookup(el('receipt-id').value.trim().toLowerCase());
  });
  var linked = new URLSearchParams(location.search).get('receipt');
  loadSnapshot().then(function () {
    if (linked) { el('receipt-id').value = linked; lookup(linked.toLowerCase()); }
  });
}());

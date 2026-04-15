/**
 * © 2026 Welco™ - All Rights Reserved
 * This file is part of the Welco Hotel Management Platform.
 * Unauthorized copying or distribution is prohibited.
 */
(function() {
  'use strict';

  // ── Copyright watermark in console ──
  var style1 = 'color:#005f73;font-size:18px;font-weight:bold;';
  var style2 = 'color:#e63946;font-size:12px;';
  var style3 = 'color:#555;font-size:11px;';
  console.log('%c© 2026 Welco™', style1);
  console.log('%c⚠️  WARNING: This is proprietary software.', style2);
  console.log('%cUnauthorized copying or reverse engineering is prohibited by law.\nWelco™ is a registered trademark. welco.app', style3);

  // ── Disable right-click context menu ──
  document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    return false;
  });

  // ── Disable common keyboard shortcuts for devtools ──
  document.addEventListener('keydown', function(e) {
    // F12
    if (e.keyCode === 123) { e.preventDefault(); return false; }
    // Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C
    if (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
      e.preventDefault(); return false;
    }
    // Ctrl+U (view source)
    if (e.ctrlKey && e.keyCode === 85) { e.preventDefault(); return false; }
    // Ctrl+S (save page)
    if (e.ctrlKey && e.keyCode === 83) { e.preventDefault(); return false; }
  });

  // ── Disable text selection on UI elements ──
  document.addEventListener('selectstart', function(e) {
    if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
      e.preventDefault();
    }
  });

  // ── Console warning repeater ──
  var _loop = setInterval(function() {
    console.clear();
    console.log('%c© 2026 Welco™ — Proprietary Software. Do not copy.', 'color:#005f73;font-size:14px;font-weight:bold;');
  }, 3000);

  // ── Watermark stamp in DOM ──
  window.addEventListener('load', function() {
    var wm = document.createElement('div');
    wm.id = '_welco_wm';
    wm.style.cssText = [
      'position:fixed', 'bottom:0', 'right:0', 'z-index:99999',
      'font-size:9px', 'color:rgba(0,95,115,0.35)', 'pointer-events:none',
      'padding:4px 8px', 'font-family:monospace', 'letter-spacing:0.5px',
      'user-select:none', '-webkit-user-select:none'
    ].join(';');
    wm.textContent = '© 2026 Welco™';
    document.body.appendChild(wm);
  });

})();
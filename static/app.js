(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  document.addEventListener('DOMContentLoaded', function () {

    // Progress bars: widths come from data attributes (inline styles are blocked by our CSP)
    document.querySelectorAll('[data-progress]').forEach(function (el) {
      var value = Math.max(0, Math.min(100, parseFloat(el.getAttribute('data-progress')) || 0));
      requestAnimationFrame(function () { el.style.width = value + '%'; });
    });

    // Filters start open on desktop, collapsed on phones
    var filters = document.querySelector('details.filters');
    if (filters && window.matchMedia('(min-width: 900px)').matches) { filters.open = true; }

    // Dismiss flash messages
    document.querySelectorAll('.alert-close').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var alert = btn.closest('.alert');
        if (alert) { alert.remove(); }
      });
    });

    drawCharts();
  });

  // Confirm destructive actions and stop double submits
  document.addEventListener('submit', function (event) {
    var form = event.target;
    var message = form.getAttribute && form.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
      event.preventDefault();
      return;
    }
    var button = form.querySelector('button[type="submit"]');
    if (button) { setTimeout(function () { button.disabled = true; }, 0); }
  });

  // Re-enable buttons when returning via the browser's back button
  window.addEventListener('pageshow', function (event) {
    if (event.persisted) {
      document.querySelectorAll('button[type="submit"]:disabled').forEach(function (b) { b.disabled = false; });
    }
  });

  function drawCharts() {
    var dataEl = document.getElementById('chart-data');
    if (!dataEl) { return; }

    if (!window.Chart) {
      document.querySelectorAll('.chart-box').forEach(function (box) { box.classList.add('is-unavailable'); });
      return;
    }

    var data = JSON.parse(dataEl.textContent);
    var css = getComputedStyle(document.documentElement);
    var token = function (name) { return css.getPropertyValue(name).trim(); };
    var muted = token('--muted'), line = token('--line'), brand = token('--brand'),
        brandSoft = token('--brand-soft'), surface = token('--surface');
    var rupees = function (v) { return '\u20B9' + Number(v).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); };
    var compact = new Intl.NumberFormat('en-IN', { notation: 'compact', maximumFractionDigits: 1 });

    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.color = muted;
    Chart.defaults.animation = reduceMotion ? false : { duration: 600 };

    var trendEl = document.getElementById('trendChart');
    if (trendEl) {
      var last = data.trend.values.length - 1;
      new Chart(trendEl, {
        type: 'bar',
        data: {
          labels: data.trend.labels,
          datasets: [{
            data: data.trend.values,
            backgroundColor: data.trend.values.map(function (_, i) { return i === last ? brand : brandSoft; }),
            borderRadius: 8,
            borderSkipped: false,
            maxBarThickness: 44
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: { displayColors: false, callbacks: { label: function (ctx) { return rupees(ctx.parsed.y); } } }
          },
          scales: {
            x: { grid: { display: false }, border: { display: false } },
            y: {
              beginAtZero: true,
              border: { display: false },
              grid: { color: line },
              ticks: { maxTicksLimit: 5, callback: function (v) { return '\u20B9' + compact.format(v); } }
            }
          }
        }
      });
    }

    var catEl = document.getElementById('categoryChart');
    if (catEl && data.categories.values.length) {
      new Chart(catEl, {
        type: 'doughnut',
        data: {
          labels: data.categories.labels,
          datasets: [{
            data: data.categories.values,
            backgroundColor: data.categories.colors,
            borderColor: surface,
            borderWidth: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '68%',
          plugins: {
            legend: { display: false },
            tooltip: { callbacks: { label: function (ctx) { return ' ' + ctx.label + ': ' + rupees(ctx.parsed); } } }
          }
        }
      });
    }
  }
})();

(() => {
  const $ = (sel, el=document) => el.querySelector(sel);
  const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));

  // ─────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────
  function pad(n){ return n < 10 ? '0' + n : '' + n; }

  function toInputLocal(dt){
    const y = dt.getFullYear(), m = pad(dt.getMonth()+1), d = pad(dt.getDate());
    const H = pad(dt.getHours()), M = pad(dt.getMinutes());
    return `${y}-${m}-${d}T${H}:${M}`;
  }

  function fromInputLocal(s){
    return new Date(s.replace('T',' ') + ':00');
  }

  function fmtLocal(iso){
    const d = new Date(iso);
    return d.toLocaleString();
  }

  function number(n){
    return n.toLocaleString();
  }

  function parseGoDuration(str){
    let s = (str || '').trim();
    if (!s) return null;
    if (s[0] === '+' || s[0] === '-'){
      if (s[0] === '-') return null;
      s = s.slice(1);
    }
    if (!s) return null;
    const unitMap = {
      ns:1e-6, us:1e-3, 'µs':1e-3, 'μs':1e-3, ms:1,
      s:1000, m:60000, h:3600000, d:86400000, day:86400000,
      w:604800000, week:604800000
    };
    const re = /(\d+(?:\.\d+)?)(day|week|ns|us|µs|μs|ms|s|m|h|d|w)/gi;
    let last = 0, total = 0, match;
    while ((match = re.exec(s))){
      if (match.index !== last) return null;
      const value = parseFloat(match[1]);
      if (!Number.isFinite(value)) return null;
      let unit = match[2].toLowerCase();
      if (unit === 'µs' || unit === 'μs') unit = 'us';
      const factor = unitMap[unit];
      if (!factor) return null;
      total += value * factor;
      last = re.lastIndex;
    }
    if (last !== s.length || total <= 0) return null;
    return Math.round(total);
  }

  function tzOffsetStr(){
    const m = new Date().getTimezoneOffset();
    const sign = m > 0 ? '-' : '+';
    const mm = Math.abs(m);
    return `${sign}${pad(Math.floor(mm/60))}:${pad(mm%60)}`;
  }

  function autoBucket(fromSec, toSec){
    const span = toSec - fromSec;
    if (span <= 3*3600) return 'minute';
    if (span <= 4*86400) return 'hour';
    return 'day';
  }

  function qstr(params){
    return Object.entries(params).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  }

  // ─────────────────────────────────────────────────────────────
  // Toast Notifications
  // ─────────────────────────────────────────────────────────────
  function showToast(message, type = 'error', duration = 5000){
    const container = $('#toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-message">${escapeHtml(message)}</span>
      <button class="toast-close" aria-label="Close">&times;</button>
    `;

    const close = toast.querySelector('.toast-close');
    close.addEventListener('click', () => toast.remove());

    container.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
  }

  function escapeHtml(str){
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ─────────────────────────────────────────────────────────────
  // Loading States
  // ─────────────────────────────────────────────────────────────
  let loadingCount = 0;

  function setLoading(isLoading){
    const content = $('#mainContent');
    if (!content) return;
    if (isLoading){
      loadingCount++;
      content.classList.add('loading');
    } else {
      loadingCount = Math.max(0, loadingCount - 1);
      if (loadingCount === 0) content.classList.remove('loading');
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Last Updated Indicator
  // ─────────────────────────────────────────────────────────────
  let lastUpdateTime = null;
  let updateIntervalId = null;

  function updateLastUpdatedDisplay(){
    const el = $('#lastUpdated');
    if (!el || !lastUpdateTime) return;

    const seconds = Math.floor((Date.now() - lastUpdateTime) / 1000);
    if (seconds < 5){
      el.textContent = 'Updated just now';
      el.classList.remove('stale');
    } else if (seconds < 60){
      el.textContent = `Updated ${seconds}s ago`;
      el.classList.toggle('stale', seconds > 30);
    } else {
      const mins = Math.floor(seconds / 60);
      el.textContent = `Updated ${mins}m ago`;
      el.classList.add('stale');
    }
  }

  function markUpdated(){
    lastUpdateTime = Date.now();
    updateLastUpdatedDisplay();
  }

  // ─────────────────────────────────────────────────────────────
  // API Calls
  // ─────────────────────────────────────────────────────────────
  async function jget(url){
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  // ─────────────────────────────────────────────────────────────
  // Host Filter
  // ─────────────────────────────────────────────────────────────
  async function loadHosts(from, to){
    try {
      const sel = $('#hostFilter');
      if (!sel) return;
      const hosts = await jget(`/api/hosts?${qstr({from, to})}`);
      const current = sel.value;
      sel.innerHTML = '<option value="">All hosts</option>';
      hosts.forEach(h => {
        const opt = document.createElement('option');
        opt.value = h;
        opt.textContent = h;
        if (h === current) opt.selected = true;
        sel.appendChild(opt);
      });
    } catch (e) {
      console.error('load hosts:', e);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // User Menu
  // ─────────────────────────────────────────────────────────────
  let userMenuOpen = false;
  let userMenuBound = false;

  function setUserMenuVisible(show){
    const menu = $('#userMenu');
    const toggle = $('#userBadgeToggle');
    if (!menu || !toggle) return;
    userMenuOpen = show;
    toggle.setAttribute('aria-expanded', show ? 'true' : 'false');
    menu.classList.toggle('hidden', !show);
  }

  function bindUserMenu(){
    if (userMenuBound) return;
    const toggle = $('#userBadgeToggle');
    const menu = $('#userMenu');
    const badge = $('#userBadge');
    if (!toggle || !badge || !menu) return;

    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      setUserMenuVisible(!userMenuOpen);
    });

    document.addEventListener('click', (e) => {
      if (userMenuOpen && badge && !badge.contains(e.target)){
        setUserMenuVisible(false);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') setUserMenuVisible(false);
    });

    userMenuBound = true;
  }

  async function loadSessionInfo(){
    const badge = $('#userBadge');
    if (!badge) return;
    try {
      const info = await jget('/api/session') || {};
      const label = ((info.email || info.user || '') + '').trim();
      const emailEl = $('#userEmail');
      const avatar = $('#userAvatar');

      if (!label){
        badge.classList.add('hidden');
        setUserMenuVisible(false);
        if (avatar){ avatar.classList.add('hidden'); avatar.removeAttribute('src'); }
        if (emailEl) emailEl.textContent = '';
        return;
      }

      bindUserMenu();
      setUserMenuVisible(false);
      if (emailEl) emailEl.textContent = label;
      if (avatar){
        if (info.avatar_url){
          avatar.src = info.avatar_url;
          avatar.classList.remove('hidden');
        } else {
          avatar.classList.add('hidden');
          avatar.removeAttribute('src');
        }
      }
      badge.classList.remove('hidden');
    } catch (e) {
      console.error('load session:', e);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Range Selection
  // ─────────────────────────────────────────────────────────────
  function inferRange(preset){
    const now = new Date();
    let from, to;

    switch(preset){
      case '24h':
        to = now; from = new Date(now.getTime() - 24*3600*1000);
        break;
      case '7d':
        to = now; from = new Date(now.getTime() - 7*86400*1000);
        break;
      case '2w':
        to = now; from = new Date(now.getTime() - 14*86400*1000);
        break;
      case '1m':
        to = now; from = new Date(now.getTime() - 30*86400*1000);
        break;
      case 'today':
        to = now; from = new Date(now); from.setHours(0,0,0,0);
        break;
      case 'duration': {
        const input = $('#duration');
        const ms = parseGoDuration(input.value);
        if (!ms){
          input.classList.add('input-error');
          return null;
        }
        input.classList.remove('input-error');
        to = now; from = new Date(now.getTime() - ms);
        break;
      }
      default: { // custom
        const fromS = $('#from').value, toS = $('#to').value;
        if (!fromS || !toS) return null;
        from = fromInputLocal(fromS); to = fromInputLocal(toS);
      }
    }
    return { from, to };
  }

  function setCustomInputsVisible(preset){
    const showCustom = preset === 'custom';
    const showDuration = preset === 'duration';
    $$('#from, #to').forEach(el => el.classList.toggle('hidden', !showCustom));
    const durationInput = $('#duration');
    if (durationInput){
      const wasHidden = durationInput.classList.contains('hidden');
      durationInput.classList.toggle('hidden', !showDuration);
      durationInput.disabled = !showDuration;
      if (showDuration && wasHidden) setTimeout(() => durationInput.focus(), 0);
    }
  }

  function setCustomFromTo(range){
    $('#from').value = toInputLocal(range.from);
    $('#to').value = toInputLocal(range.to);
  }

  // ─────────────────────────────────────────────────────────────
  // Auto-Refresh
  // ─────────────────────────────────────────────────────────────
  const REFRESH_INTERVAL = 10000;
  let autoRefreshEnabled = true;
  let refreshIntervalId = null;

  function toggleAutoRefresh(){
    autoRefreshEnabled = !autoRefreshEnabled;
    const button = $('#refresh');
    if (autoRefreshEnabled){
      button.textContent = 'Live';
      button.classList.remove('paused');
      button.classList.add('live');
      refreshIntervalId = setInterval(refresh, REFRESH_INTERVAL);
    } else {
      button.textContent = 'Paused';
      button.classList.remove('live');
      button.classList.add('paused');
      if (refreshIntervalId){
        clearInterval(refreshIntervalId);
        refreshIntervalId = null;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Chart.js Configuration
  // ─────────────────────────────────────────────────────────────
  let reqChart = null, errChart = null, uaFamChart = null, hostsChart = null;

  const chartColors = {
    accent: '#5aa6ff',
    accentGradient: ['rgba(90,166,255,0.8)', 'rgba(90,166,255,0.2)'],
    error: '#ff7a7a',
    errorGradient: ['rgba(255,122,122,0.8)', 'rgba(255,122,122,0.2)'],
    palette: ['#5aa6ff','#ff7a7a','#3dd68c','#f0b429','#a77bff','#ff8ec0','#33c3ff','#ffd166']
  };

  function createGradient(ctx, colorStops){
    const gradient = ctx.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, colorStops[0]);
    gradient.addColorStop(1, colorStops[1]);
    return gradient;
  }

  function chartOptions(){
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          mode: 'index',
          intersect: false,
          backgroundColor: '#1a1e26',
          titleColor: '#e8ecf1',
          bodyColor: '#8892a2',
          borderColor: '#252b36',
          borderWidth: 1,
          padding: 12,
          cornerRadius: 8
        }
      },
      scales: {
        x: {
          ticks: { autoSkip: true, maxRotation: 0, color: '#8892a2', font: { size: 11 } },
          grid: { color: 'rgba(37,43,54,0.5)', drawBorder: false }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#8892a2', font: { size: 11 } },
          grid: { color: 'rgba(37,43,54,0.5)', drawBorder: false }
        }
      },
      interaction: { mode: 'nearest', axis: 'x', intersect: false }
    };
  }

  function ensureBarChart(ctx, gradientStops){
    const gradient = createGradient(ctx, gradientStops);
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Count',
          data: [],
          backgroundColor: gradient,
          borderRadius: 4,
          borderSkipped: false
        }]
      },
      options: chartOptions()
    });
  }

  function updateBarChart(chart, labels, data){
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.update('none');
  }

  function ensurePieChart(ctx){
    return new Chart(ctx, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0, hoverOffset: 8 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1a1e26',
            titleColor: '#e8ecf1',
            bodyColor: '#8892a2',
            borderColor: '#252b36',
            borderWidth: 1,
            padding: 12,
            cornerRadius: 8,
            callbacks: {
              label: function(context) {
                const value = context.parsed;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                return `${number(value)} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }

  function updatePieChart(chart, labels, data, legendId){
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.data.datasets[0].backgroundColor = labels.map((_, i) => chartColors.palette[i % chartColors.palette.length]);
    chart.update('none');
    if (legendId) renderLegend(legendId, labels, chart.data.datasets[0].backgroundColor);
  }

  function renderLegend(id, labels, colors){
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = '';
    labels.forEach((lbl, i) => {
      const span = document.createElement('span');
      span.className = 'item';
      span.textContent = lbl;
      span.style.color = colors[i] || chartColors.accent;
      el.appendChild(span);
    });
  }

  // ─────────────────────────────────────────────────────────────
  // Table Rendering
  // ─────────────────────────────────────────────────────────────
  function renderTable(tbody, rows, rowRenderer){
    tbody.innerHTML = '';
    if (rows.length === 0){
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 100;
      td.innerHTML = '<div class="empty-state"><div class="empty-state-icon">-</div><div class="empty-state-text">No data for this period</div></div>';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    const frag = document.createDocumentFragment();
    rows.forEach(r => frag.appendChild(rowRenderer(r)));
    tbody.appendChild(frag);
  }

  function makeCell(text, cls){
    const td = document.createElement('td');
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }

  function makeTruncatedCell(text, cls, maxWidth = 280){
    const td = document.createElement('td');
    td.textContent = text;
    td.className = (cls ? cls + ' ' : '') + 'truncate';
    td.style.maxWidth = maxWidth + 'px';
    td.title = text;
    return td;
  }

  function statusClass(code){
    const c = parseInt(code, 10);
    if (c >= 200 && c < 300) return 'status-2xx';
    if (c >= 300 && c < 400) return 'status-3xx';
    if (c >= 400 && c < 500) return 'status-4xx';
    return 'status-5xx';
  }

  // ─────────────────────────────────────────────────────────────
  // Sortable Tables
  // ─────────────────────────────────────────────────────────────
  const sortState = Object.create(null);

  function bindSortHeaders(tableId, rows, sorters, defaultKey, defaultDir, onRender){
    const table = document.getElementById(tableId);
    if (!table) return;
    const thead = table.querySelector('thead');
    const state = sortState[tableId] || { key: defaultKey, dir: defaultDir };
    sortState[tableId] = state;

    function render(){
      const sorter = sorters[state.key];
      const cmp = sorter ? sorter(state.dir) : (() => 0);
      const sorted = rows.slice().sort(cmp);
      onRender(sorted);
      thead.querySelectorAll('th.sortable').forEach(th => {
        th.removeAttribute('data-sort');
        if (th.dataset.key === state.key) th.setAttribute('data-sort', state.dir);
      });
    }

    if (!thead.__sortableBound){
      thead.__sortableBound = true;
      thead.querySelectorAll('th.sortable').forEach(th => {
        th.addEventListener('click', () => {
          const key = th.dataset.key;
          if (!key) return;
          if (state.key === key){
            state.dir = state.dir === 'asc' ? 'desc' : 'asc';
          } else {
            state.key = key;
            state.dir = ['count', 'pct', 'status'].includes(key) ? 'desc' : 'asc';
          }
          render();
        });
      });
    }
    render();
  }

  // Sort helpers
  const sortNumDesc = (key) => (a, b) => (b[key] || 0) - (a[key] || 0);
  const sortStrAsc = (key) => (a, b) => String(a[key] || '').localeCompare(String(b[key] || ''));

  function makeSorters(keys){
    const sorters = {};
    keys.forEach(k => {
      if (['count', 'pct', 'status'].includes(k)){
        sorters[k] = (dir) => (a, b) => dir === 'asc' ? (a[k]||0) - (b[k]||0) : (b[k]||0) - (a[k]||0);
      } else {
        sorters[k] = (dir) => (a, b) => dir === 'asc' ? sortStrAsc(k)(a, b) : sortStrAsc(k)(b, a);
      }
    });
    return sorters;
  }

  // ─────────────────────────────────────────────────────────────
  // Row Renderers (reusable)
  // ─────────────────────────────────────────────────────────────
  function createPathRow(r, onPathClick){
    const tr = document.createElement('tr');
    const a = document.createElement('a');
    a.textContent = r.path;
    a.href = '#';
    a.addEventListener('click', (e) => { e.preventDefault(); onPathClick(r.path); });
    const tdPath = document.createElement('td');
    tdPath.appendChild(a);
    tr.appendChild(tdPath);
    tr.appendChild(makeCell(number(r.count), 'num'));
    return tr;
  }

  function createRefRow(r){
    const tr = document.createElement('tr');
    tr.appendChild(makeTruncatedCell(r.referrer || '(none)', '', 220));
    tr.appendChild(makeCell(number(r.count), 'num'));
    return tr;
  }

  function createFamilyRow(r){
    const tr = document.createElement('tr');
    tr.appendChild(makeCell(r.family));
    tr.appendChild(makeCell(number(r.count), 'num'));
    tr.appendChild(makeCell((r.pct || 0).toFixed(1) + '%', 'pct'));
    return tr;
  }

  function createUARow(r){
    const tr = document.createElement('tr');
    tr.appendChild(makeTruncatedCell(r.ua, '', 320));
    tr.appendChild(makeCell(number(r.count), 'num'));
    return tr;
  }

  function createHostRow(r, onHostClick){
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    const span = document.createElement('span');
    span.textContent = r.host;
    span.className = 'clickable';
    span.addEventListener('click', () => onHostClick(r.host));
    td.appendChild(span);
    tr.appendChild(td);
    tr.appendChild(makeCell(number(r.count), 'num'));
    tr.appendChild(makeCell((r.pct || 0).toFixed(1) + '%', 'pct'));
    return tr;
  }

  function createStatusRow(r, onStatusClick){
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.textContent = r.status;
    td.className = statusClass(r.status) + ' clickable';
    td.addEventListener('click', () => onStatusClick(r.status));
    tr.appendChild(td);
    tr.appendChild(makeCell(number(r.count), 'num'));
    return tr;
  }

  // ─────────────────────────────────────────────────────────────
  // Main Refresh Function
  // ─────────────────────────────────────────────────────────────
  async function refresh(){
    const preset = $('#rangePreset').value;
    const range = inferRange(preset);
    if (!range){
      if (preset !== 'duration') showToast('Select a valid range', 'warning');
      return;
    }

    setLoading(true);

    try {
      const from = Math.floor(range.from.getTime() / 1000);
      const to = Math.floor(range.to.getTime() / 1000);
      let bucketSel = $('#bucket').value;
      if (bucketSel === 'auto') bucketSel = autoBucket(from, to);
      const tz = tzOffsetStr();

      await loadHosts(from, to);
      const hostSel = $('#hostFilter');
      const host = hostSel ? hostSel.value : '';
      const baseParams = host ? { from, to, host } : { from, to };
      const qp = (extra = {}) => qstr({ ...baseParams, ...extra });

      // Fetch all data
      const [summary, tsReq, tsErr, topPaths, topRef, uaFam, uaTop, topHosts, stat] = await Promise.all([
        jget(`/api/summary?${qp()}`),
        jget(`/api/timeseries/requests?${qp({ bucket: bucketSel, tz })}`),
        jget(`/api/timeseries/errors?${qp({ bucket: bucketSel, tz })}`),
        jget(`/api/top/paths?${qp({ limit: 15 })}`),
        jget(`/api/top/referrers?${qp({ limit: 15 })}`),
        jget(`/api/top/ua_families?${qp({ limit: 12 })}`),
        jget(`/api/top/ua?${qp({ limit: 12 })}`),
        jget(`/api/top/hosts?${qp({ limit: 12 })}`),
        jget(`/api/status?${qp()}`)
      ]);

      // Summary cards
      $('#sumRequests').textContent = number(summary.requests || 0);
      $('#sumUnique').textContent = number(summary.unique_remote || 0);
      $('#sumErrors').textContent = number(summary.errors || 0);
      $('#sumLast').textContent = summary.last_request ? fmtLocal(summary.last_request) : '-';
      const totalReq = summary.requests || 0;

      // Charts
      const reqLabels = tsReq.map(p => new Date(p.t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
      const reqData = tsReq.map(p => p.count);
      const errLabels = tsErr.map(p => new Date(p.t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
      const errData = tsErr.map(p => p.count);

      if (!reqChart) reqChart = ensureBarChart($('#chartRequests').getContext('2d'), chartColors.accentGradient);
      if (!errChart) errChart = ensureBarChart($('#chartErrors').getContext('2d'), chartColors.errorGradient);
      updateBarChart(reqChart, reqLabels, reqData);
      updateBarChart(errChart, errLabels, errData);

      // Callback for filtering
      const onPathClick = (path) => filterRequests({ path_like: path }, from, to);
      const onHostClick = (h) => {
        const sel = $('#hostFilter');
        if (sel) { sel.value = h; refresh(); }
      };
      const onStatusClick = (status) => filterRequests({ status }, from, to);

      // Top Paths
      const pathsData = topPaths.slice().sort(sortNumDesc('count'));
      bindSortHeaders('topPaths', pathsData, makeSorters(['path', 'count']), 'count', 'desc',
        (rows) => renderTable($('#topPaths tbody'), rows, r => createPathRow(r, onPathClick)));

      // Top Referrers
      const refData = topRef.slice().sort(sortNumDesc('count'));
      bindSortHeaders('topRef', refData, makeSorters(['referrer', 'count']), 'count', 'desc',
        (rows) => renderTable($('#topRef tbody'), rows, createRefRow));

      // UA Families
      const uaFamRows = uaFam.map(r => ({ family: r.family, count: r.count, pct: totalReq > 0 ? (r.count / totalReq) * 100 : 0 }));
      bindSortHeaders('uaFamilies', uaFamRows, makeSorters(['family', 'count', 'pct']), 'count', 'desc',
        (rows) => renderTable($('#uaFamilies tbody'), rows, createFamilyRow));

      // UA Pie Chart
      {
        const topN = 6;
        const labels = uaFam.slice(0, topN).map(r => r.family);
        const data = uaFam.slice(0, topN).map(r => r.count);
        const others = uaFam.slice(topN).reduce((acc, r) => acc + r.count, 0);
        if (others > 0){ labels.push('Other'); data.push(others); }
        if (!uaFamChart) uaFamChart = ensurePieChart($('#chartUAFam').getContext('2d'));
        updatePieChart(uaFamChart, labels, data, 'legendUAFam');
      }

      // Top User Agents
      const uaTopRows = uaTop.slice().sort(sortNumDesc('count'));
      bindSortHeaders('uaTop', uaTopRows, makeSorters(['ua', 'count']), 'count', 'desc',
        (rows) => renderTable($('#uaTop tbody'), rows, createUARow));

      // Hosts Table
      const hostsRows = topHosts.map(r => ({ host: r.host, count: r.count, pct: totalReq > 0 ? (r.count / totalReq) * 100 : 0 }));
      bindSortHeaders('hostsTable', hostsRows, makeSorters(['host', 'count', 'pct']), 'count', 'desc',
        (rows) => renderTable($('#hostsTable tbody'), rows, r => createHostRow(r, onHostClick)));

      // Hosts Pie Chart
      {
        const topN = 6;
        const labels = topHosts.slice(0, topN).map(r => r.host);
        const data = topHosts.slice(0, topN).map(r => r.count);
        const others = topHosts.slice(topN).reduce((acc, r) => acc + r.count, 0);
        if (others > 0){ labels.push('Other'); data.push(others); }
        if (!hostsChart) hostsChart = ensurePieChart($('#chartHosts').getContext('2d'));
        updatePieChart(hostsChart, labels, data, 'legendHosts');
      }

      // Status Table
      const statusRows = stat.slice().sort(sortNumDesc('count'));
      bindSortHeaders('statusTbl', statusRows, makeSorters(['status', 'count']), 'count', 'desc',
        (rows) => renderTable($('#statusTbl tbody'), rows, r => createStatusRow(r, onStatusClick)));

      // Recent Requests & Errors
      await filterRequests({}, from, to);
      const errs = await jget(`/api/errors?${qp({ limit: 50 })}`);
      renderTable($('#errorsTbl tbody'), errs, r => {
        const tr = document.createElement('tr');
        tr.appendChild(makeCell(fmtLocal(r.ts)));
        tr.appendChild(makeCell(r.level));
        tr.appendChild(makeCell(r.pid));
        tr.appendChild(makeCell(r.tid));
        const msg = r.message.length > 200 ? r.message.slice(0, 200) + '...' : r.message;
        tr.appendChild(makeTruncatedCell(msg, '', 400));
        return tr;
      });

      markUpdated();
    } catch (err) {
      console.error('Refresh failed:', err);
      showToast('Failed to load data: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Filter Requests
  // ─────────────────────────────────────────────────────────────
  async function filterRequests(extra = {}, fromSec = null, toSec = null){
    const preset = $('#rangePreset').value;
    const range = inferRange(preset);
    if (!range){
      if (preset !== 'duration') showToast('Select a valid range', 'warning');
      return;
    }
    const from = fromSec ?? Math.floor(range.from.getTime() / 1000);
    const to = toSec ?? Math.floor(range.to.getTime() / 1000);
    const base = { from, to, limit: 50, offset: 0, ...extra };
    const hostSel = $('#hostFilter');
    const host = hostSel ? hostSel.value : '';
    if (host) base.host = host;

    try {
      const rows = await jget(`/api/requests?${qstr(base)}`);
      renderTable($('#reqTbl tbody'), rows, r => {
        const tr = document.createElement('tr');
        tr.appendChild(makeCell(fmtLocal(r.ts)));
        tr.appendChild(makeTruncatedCell(r.remote || (r.xff || ''), 'truncate-sm', 120));
        tr.appendChild(makeCell(r.method));
        tr.appendChild(makeTruncatedCell(r.path, '', 200));
        const tdStatus = makeCell(r.status);
        tdStatus.className = statusClass(r.status);
        tr.appendChild(tdStatus);
        tr.appendChild(makeCell(number(r.bytes), 'num'));
        tr.appendChild(makeTruncatedCell(r.referer || '', '', 150));
        tr.appendChild(makeTruncatedCell(r.ua || '', '', 200));
        return tr;
      });
    } catch (err) {
      console.error('Filter requests failed:', err);
      showToast('Failed to load requests', 'error');
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Keyboard Shortcuts
  // ─────────────────────────────────────────────────────────────
  function handleKeyboardShortcuts(e){
    // Ignore if typing in an input
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;

    switch(e.key.toLowerCase()){
      case 'r':
        e.preventDefault();
        refresh();
        break;
      case 'p':
        e.preventDefault();
        toggleAutoRefresh();
        break;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Initialization
  // ─────────────────────────────────────────────────────────────
  function init(){
    loadSessionInfo();

    // Restore saved UI settings
    const savedPreset = localStorage.getItem('lt_range_preset');
    const savedBucket = localStorage.getItem('lt_bucket');
    const durationInput = $('#duration');
    const savedDuration = localStorage.getItem('lt_duration');
    durationInput.value = savedDuration || '5m';

    // Duration input handlers
    durationInput.addEventListener('change', () => {
      const val = durationInput.value.trim();
      localStorage.setItem('lt_duration', val);
      const valid = parseGoDuration(val);
      durationInput.classList.toggle('input-error', !valid);
      if (valid && $('#rangePreset').value === 'duration') refresh();
    });

    durationInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter'){
        e.preventDefault();
        const val = durationInput.value.trim();
        localStorage.setItem('lt_duration', val);
        const valid = parseGoDuration(val);
        durationInput.classList.toggle('input-error', !valid);
        if (valid && $('#rangePreset').value === 'duration') refresh();
      }
    });

    // Restore preset
    if (savedPreset){
      const sel = $('#rangePreset');
      if ([...sel.options].some(o => o.value === savedPreset)){
        sel.value = savedPreset;
        setCustomInputsVisible(savedPreset);
      }
    }

    // Restore bucket
    if (savedBucket){
      const sel = $('#bucket');
      if ([...sel.options].some(o => o.value === savedBucket)) sel.value = savedBucket;
    }

    setCustomInputsVisible($('#rangePreset').value);

    // Default custom inputs
    const now = new Date(), from7 = new Date(now.getTime() - 7*86400*1000);
    setCustomFromTo({ from: from7, to: now });

    // Event listeners
    $('#rangePreset').addEventListener('change', e => {
      const preset = e.target.value;
      localStorage.setItem('lt_range_preset', preset);
      setCustomInputsVisible(preset);
      if (preset === 'duration'){
        const val = $('#duration').value.trim();
        const valid = parseGoDuration(val);
        const di = $('#duration');
        di.classList.toggle('input-error', !valid);
        if (valid) refresh();
      } else if (preset !== 'custom'){
        refresh();
      }
    });

    $('#refresh').addEventListener('click', toggleAutoRefresh);
    $('#bucket').addEventListener('change', (e) => { localStorage.setItem('lt_bucket', e.target.value); refresh(); });

    const hostFilter = $('#hostFilter');
    if (hostFilter) hostFilter.addEventListener('change', refresh);

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);

    // Resize handler with proper cleanup
    let resizeTimeout;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        if (reqChart) reqChart.resize();
        if (errChart) errChart.resize();
        if (uaFamChart) uaFamChart.resize();
        if (hostsChart) hostsChart.resize();
      }, 150);
    });

    // Last updated interval
    updateIntervalId = setInterval(updateLastUpdatedDisplay, 1000);

    // Initial load
    refresh().then(() => {
      refreshIntervalId = setInterval(refresh, REFRESH_INTERVAL);
      const button = $('#refresh');
      button.textContent = 'Live';
      button.classList.add('live');
    }).catch(err => {
      console.error(err);
      showToast('Failed to load data: ' + err.message, 'error');
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();

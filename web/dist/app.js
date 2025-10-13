(() => {
  const $ = (sel, el=document) => el.querySelector(sel);
  const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));

  function pad(n){return n<10?"0"+n:""+n}
  function toInputLocal(dt){ // Date -> yyyy-MM-ddTHH:mm
    const y=dt.getFullYear(); const m=pad(dt.getMonth()+1); const d=pad(dt.getDate()); const H=pad(dt.getHours()); const M=pad(dt.getMinutes());
    return `${y}-${m}-${d}T${H}:${M}`;
  }
  function fromInputLocal(s){ // local time string -> Date
    // Treat as local time
    return new Date(s.replace('T',' ') + ':00');
  }
  function toRFC3339(dt){ return new Date(dt.getTime() - dt.getMilliseconds()).toISOString().replace(/\.\d{3}Z$/, 'Z') }
  function fmtLocal(iso){ const d=new Date(iso); return d.toLocaleString() }
  function number(n){ return n.toLocaleString() }
  function parseGoDuration(str){
    let s = (str || '').trim();
    if (!s) return null;
    if (s[0] === '+' || s[0] === '-'){
      if (s[0] === '-') return null;
      s = s.slice(1);
    }
    if (!s) return null;
    const unitMap = {
      ns:1e-6,
      us:1e-3,
      µs:1e-3,
      μs:1e-3,
      ms:1,
      s:1000,
      m:60000,
      h:3600000,
      d:86400000,
      day:86400000,
      w:604800000,
      week:604800000
    };
    const re = /(\d+(?:\.\d+)?)(day|week|ns|us|µs|μs|ms|s|m|h|d|w)/gi;
    let last = 0;
    let total = 0;
    let match;
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
    if (last !== s.length) return null;
    if (total <= 0) return null;
    return Math.round(total);
  }

  function tzOffsetStr(){
    // getTimezoneOffset returns minutes to add to local to get UTC (e.g., EDT -4h => +240)
    const m = new Date().getTimezoneOffset();
    const sign = m>0 ? '-' : '+'; // positive means west => negative offset
    const mm = Math.abs(m);
    const hh = Math.floor(mm/60); const rr = mm%60;
    return `${sign}${pad(hh)}:${pad(rr)}`;
  }

  function autoBucket(fromSec, toSec){
    const span = toSec - fromSec;
    if (span <= 3*3600) return 'minute';
    if (span <= 4*86400) return 'hour';
    return 'day';
  }

  async function jget(url){
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  function qstr(params){
    return Object.entries(params).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
  }

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
      if (current && sel.value !== current) {
        sel.value = current;
      }
    } catch (e) {
      console.error('load hosts:', e);
    }
  }

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
      if (!userMenuOpen) return;
      if (badge && !badge.contains(e.target)) {
        setUserMenuVisible(false);
      }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        setUserMenuVisible(false);
      }
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
      if (!label) {
        badge.classList.add('hidden');
        setUserMenuVisible(false);
        if (avatar) {
          avatar.classList.add('hidden');
          avatar.removeAttribute('src');
        }
        if (emailEl) emailEl.textContent = '';
        return;
      }
      bindUserMenu();
      setUserMenuVisible(false);
      if (emailEl) {
        emailEl.textContent = label;
      }
      if (avatar) {
        if (info.avatar_url) {
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

  function inferRange(preset){
    const now = new Date();
    let from, to;
    if (preset === '24h') { to = now; from = new Date(now.getTime() - 24*3600*1000); }
    else if (preset === '7d') { to = now; from = new Date(now.getTime() - 7*86400*1000); }
    else if (preset === '2w') { to = now; from = new Date(now.getTime() - 14*86400*1000); }
    else if (preset === '1m') { to = now; from = new Date(now.getTime() - 30*86400*1000); }
    else if (preset === 'duration') {
      const input = $('#duration');
      const ms = parseGoDuration(input.value);
      if (!ms) {
        if (input) input.classList.add('input-error');
        return null;
      }
      if (input) input.classList.remove('input-error');
      to = now;
      from = new Date(now.getTime() - ms);
    }
    else if (preset === 'today') {
      to = now;
      from = new Date(now); from.setHours(0,0,0,0);
    } else { // custom; read inputs
      const fromS = $('#from').value; const toS = $('#to').value;
      if (!fromS || !toS) return null;
      from = fromInputLocal(fromS); to = fromInputLocal(toS);
    }
    return { from, to };
  }

  function setCustomInputsVisible(preset){
    const showCustom = preset === 'custom';
    const showDuration = preset === 'duration';
    $$('#from, #to').forEach(el => el.classList.toggle('hidden', !showCustom));
    const durationInput = $('#duration');
    if (durationInput) {
      const wasHidden = durationInput.classList.contains('hidden');
      durationInput.classList.toggle('hidden', !showDuration);
      durationInput.disabled = !showDuration;
      if (showDuration && wasHidden) {
        setTimeout(() => durationInput.focus(), 0);
      }
    }
  }

  function setCustomFromTo(range){
    $('#from').value = toInputLocal(range.from);
    $('#to').value = toInputLocal(range.to);
  }

  // Auto-refresh state
  let autoRefreshEnabled = true;
  let refreshInterval = null;

  // Chart.js helpers
  let reqChart = null, errChart = null, uaFamChart = null, hostsChart = null;
  const chartOptions = (title) => ({
    responsive:true, maintainAspectRatio:false,
    plugins:{
      legend:{display:false},
      tooltip:{mode:'index', intersect:false},
      title:{display:false, text:title}
    },
    scales:{
      x:{ticks:{autoSkip:true, maxRotation:0}, grid:{color:'#2a2f3a'}},
      y:{beginAtZero:true, grid:{color:'#2a2f3a'}}
    }
  });
  function ensureChart(ctx, color){
    const cfg = {type:'bar', data:{labels:[], datasets:[{label:'Count', data:[], backgroundColor:color}]}, options: chartOptions()};
    return new Chart(ctx, cfg);
  }
  function updateChart(chart, labels, data){
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.update('none');
  }
  function ensurePie(ctx){
    const cfg = {type:'pie', data:{labels:[], datasets:[{data:[], backgroundColor:[]} ]}, options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}}};
    return new Chart(ctx, cfg);
  }
  function updatePie(chart, labels, data, legendId){
    const palette = ['#5aa6ff','#ff7a7a','#12c48b','#ffba3a','#a77bff','#ff8ec0','#33c3ff','#ffd166'];
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.data.datasets[0].backgroundColor = labels.map((_,i)=>palette[i%palette.length]);
    chart.update('none');
    // Custom legend with colored text
    if (legendId) {
      renderLegend(legendId, labels, chart.data.datasets[0].backgroundColor);
    }
  }

  function renderLegend(id, labels, colors){
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = '';
    labels.forEach((lbl, i) => {
      const span = document.createElement('span');
      span.className = 'item';
      span.textContent = lbl;
      span.style.color = colors[i] || '#5aa6ff';
      el.appendChild(span);
    });
  }

  function renderTable(tbody, rows, rowRenderer){
    tbody.innerHTML = '';
    const frag = document.createDocumentFragment();
    rows.forEach(r => frag.appendChild(rowRenderer(r)));
    tbody.appendChild(frag);
  }

  function makeCell(text, cls){ const td=document.createElement('td'); td.textContent=text; if(cls) td.className=cls; return td }

  function statusClass(code){
    const c = parseInt(code,10); if (c>=200 && c<300) return 'status-2xx'; if (c>=300 && c<400) return 'status-3xx'; if (c>=400 && c<500) return 'status-4xx'; return 'status-5xx';
  }

  // Bind clickable headers for a table; sorters is an object: key -> (dir)=>cmpFn
  const sortState = Object.create(null); // tableId -> {key, dir}
  function bindSortHeaders(tableId, rows, sorters, defaultKey, defaultDir, onRender){
    const table = document.getElementById(tableId);
    if (!table) return;
    const thead = table.querySelector('thead');
    const state = sortState[tableId] || {key: defaultKey, dir: defaultDir};
    sortState[tableId] = state;
    function render(){
      const sorter = sorters[state.key];
      const cmp = sorter ? sorter(state.dir) : (()=>0);
      const sorted = rows.slice().sort(cmp);
      onRender(sorted);
      thead.querySelectorAll('th.sortable').forEach(th=>{
        th.removeAttribute('data-sort');
        if (th.dataset.key === state.key) th.setAttribute('data-sort', state.dir);
      });
    }
    if (!thead.__sortableBound){
      thead.__sortableBound = true;
      thead.querySelectorAll('th.sortable').forEach(th=>{
        th.addEventListener('click', ()=>{
          const key = th.dataset.key;
          if (!key) return;
          if (state.key === key){ state.dir = (state.dir==='asc'?'desc':'asc'); }
          else { state.key = key; state.dir = (key==='count' || key==='pct' || key==='status') ? 'desc' : 'asc'; }
          render();
        });
      });
    }
    render();
  }

  async function refresh(){
    const preset = $('#rangePreset').value;
    let range = inferRange(preset);
    if (!range) {
      if (preset !== 'duration') alert('Select a valid range.');
      return;
    }
    const from = Math.floor(range.from.getTime()/1000);
    const to = Math.floor(range.to.getTime()/1000);
    let bucketSel = $('#bucket').value;
    if (bucketSel === 'auto') bucketSel = autoBucket(from, to);
    const tz = tzOffsetStr();

    await loadHosts(from, to);
    const hostSel = $('#hostFilter');
    const host = hostSel ? hostSel.value : '';
    const baseParams = host ? {from, to, host} : {from, to};
    const qp = (extra = {}) => qstr({...baseParams, ...extra});

    // Summary
    const summary = await jget(`/api/summary?${qp()}`);
    $('#sumRequests').textContent = number(summary.requests || 0);
    $('#sumUnique').textContent = number(summary.unique_remote || 0);
    $('#sumErrors').textContent = number(summary.errors || 0);
    $('#sumLast').textContent = summary.last_request ? fmtLocal(summary.last_request) : '–';
    const totalReq = summary.requests || 0;

    // Timeseries
    const tsReq = await jget(`/api/timeseries/requests?${qp({bucket:bucketSel,tz})}`);
    const tsErr = await jget(`/api/timeseries/errors?${qp({bucket:bucketSel,tz})}`);
    const reqLabels = tsReq.map(p => new Date(p.t).toLocaleString());
    const reqData   = tsReq.map(p => p.count);
    const errLabels = tsErr.map(p => new Date(p.t).toLocaleString());
    const errData   = tsErr.map(p => p.count);
    if (!reqChart) reqChart = ensureChart($('#chartRequests').getContext('2d'), '#5aa6ff');
    if (!errChart) errChart = ensureChart($('#chartErrors').getContext('2d'), '#ff7a7a');
    updateChart(reqChart, reqLabels, reqData);
    updateChart(errChart, errLabels, errData);

    // Top tables
    const topPaths = await jget(`/api/top/paths?${qp({limit:10})}`);
    const topRef   = await jget(`/api/top/referrers?${qp({limit:10})}`);
    const uaFam    = await jget(`/api/top/ua_families?${qp({limit:12})}`);
    const uaTop    = await jget(`/api/top/ua?${qp({limit:12})}`);
    const topHosts = await jget(`/api/top/hosts?${qp({limit:12})}`);
    // Sorting helpers
    const sortNumDesc = (key) => (a,b)=> (b[key]||0) - (a[key]||0);
    const sortStrAsc = (key) => (a,b)=> (''+(a[key]||'')).localeCompare((''+(b[key]||'')));
    // Top Paths (default: count desc)
    let pathsData = topPaths.slice().sort(sortNumDesc('count'));
    renderTable($('#topPaths tbody'), pathsData, r => {
      const tr = document.createElement('tr');
      const a = document.createElement('a'); a.textContent = r.path; a.href = '#'; a.addEventListener('click', (e)=>{e.preventDefault(); filterRequests({path_like:r.path})});
      const tdPath = document.createElement('td'); tdPath.appendChild(a);
      tr.appendChild(tdPath);
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    });
    // Clickable headers
    bindSortHeaders('topPaths', pathsData, {
      path: (dir)=> (a,b)=> dir==='asc'? sortStrAsc('path')(a,b): sortStrAsc('path')(b,a),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#topPaths tbody'), rows, r=>{
      const tr = document.createElement('tr');
      const a = document.createElement('a'); a.textContent = r.path; a.href = '#'; a.addEventListener('click', (e)=>{e.preventDefault(); filterRequests({path_like:r.path})});
      const tdPath = document.createElement('td'); tdPath.appendChild(a);
      tr.appendChild(tdPath);
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    }));

    let refData = topRef.slice().sort(sortNumDesc('count'));
    renderTable($('#topRef tbody'), refData, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.referrer || '(none)'));
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    });
    bindSortHeaders('topRef', refData, {
      referrer:(dir)=> (a,b)=> dir==='asc'? sortStrAsc('referrer')(a,b): sortStrAsc('referrer')(b,a),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#topRef tbody'), rows, r=>{
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.referrer || '(none)'));
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    }));

    // UA Families with pct
    let uaFamRows = uaFam.map(r => ({family:r.family, count:r.count, pct: totalReq>0 ? (r.count/totalReq)*100 : 0})).sort(sortNumDesc('count'));
    renderTable($('#uaFamilies tbody'), uaFamRows, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.family));
      tr.appendChild(makeCell(number(r.count),'num'));
      const pct = (r.pct||0).toFixed(1);
      tr.appendChild(makeCell(pct+'%','pct'));
      return tr;
    });
    bindSortHeaders('uaFamilies', uaFamRows, {
      family:(dir)=> (a,b)=> dir==='asc'? sortStrAsc('family')(a,b): sortStrAsc('family')(b,a),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b),
      pct:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('pct')(a,b): sortNumDesc('pct')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#uaFamilies tbody'), rows, r=>{
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.family));
      tr.appendChild(makeCell(number(r.count),'num'));
      const pct = (r.pct||0).toFixed(1);
      tr.appendChild(makeCell(pct+'%','pct'));
      return tr;
    }));
    // Pie: top 6 families + Other
    {
      const topN = 6;
      const labels = uaFam.slice(0, topN).map(r=>r.family);
      const data = uaFam.slice(0, topN).map(r=>r.count);
      const others = uaFam.slice(topN).reduce((acc,r)=>acc+r.count,0);
      if (others>0) { labels.push('Other'); data.push(others); }
      if (!uaFamChart) uaFamChart = ensurePie($('#chartUAFam').getContext('2d'));
      updatePie(uaFamChart, labels, data, 'legendUAFam');
    }
    let uaTopRows = uaTop.slice().sort(sortNumDesc('count'));
    renderTable($('#uaTop tbody'), uaTopRows, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.ua));
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    });
    bindSortHeaders('uaTop', uaTopRows, {
      ua:(dir)=> (a,b)=> dir==='asc'? sortStrAsc('ua')(a,b): sortStrAsc('ua')(b,a),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#uaTop tbody'), rows, r=>{
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.ua));
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    }));

    // Hosts with pct
    let hostsRows = topHosts.map(r => ({host:r.host, count:r.count, pct: totalReq>0 ? (r.count/totalReq)*100 : 0})).sort(sortNumDesc('count'));
    renderTable($('#hostsTable tbody'), hostsRows, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.host));
      tr.appendChild(makeCell(number(r.count),'num'));
      const pct = (r.pct||0).toFixed(1);
      tr.appendChild(makeCell(pct+'%','pct'));
      return tr;
    });
    bindSortHeaders('hostsTable', hostsRows, {
      host:(dir)=> (a,b)=> dir==='asc'? sortStrAsc('host')(a,b): sortStrAsc('host')(b,a),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b),
      pct:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('pct')(a,b): sortNumDesc('pct')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#hostsTable tbody'), rows, r=>{
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(r.host));
      tr.appendChild(makeCell(number(r.count),'num'));
      const pct = (r.pct||0).toFixed(1);
      tr.appendChild(makeCell(pct+'%','pct'));
      return tr;
    }));
    // Pie: top 6 hosts + Other
    {
      const topN = 6;
      const labels = topHosts.slice(0, topN).map(r=>r.host);
      const data = topHosts.slice(0, topN).map(r=>r.count);
      const others = topHosts.slice(topN).reduce((acc,r)=>acc+r.count,0);
      if (others>0) { labels.push('Other'); data.push(others); }
      if (!hostsChart) hostsChart = ensurePie($('#chartHosts').getContext('2d'));
      updatePie(hostsChart, labels, data, 'legendHosts');
    }

    // Status breakdown
    const stat = await jget(`/api/status?${qp()}`);
    let statusRows = stat.slice().sort(sortNumDesc('count'));
    renderTable($('#statusTbl tbody'), statusRows, r => {
      const tr = document.createElement('tr');
      const sc = statusClass(r.status);
      const tdS = document.createElement('td'); tdS.textContent = r.status; tdS.className = sc; tr.appendChild(tdS);
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    });
    bindSortHeaders('statusTbl', statusRows, {
      status:(dir)=> (a,b)=> dir==='asc'? (a.status-b.status): (b.status-a.status),
      count:(dir)=> (a,b)=> dir==='asc'? -sortNumDesc('count')(a,b): sortNumDesc('count')(a,b)
    }, 'count', 'desc', (rows)=> renderTable($('#statusTbl tbody'), rows, r=>{
      const tr = document.createElement('tr');
      const sc = statusClass(r.status);
      const tdS = document.createElement('td'); tdS.textContent = r.status; tdS.className = sc; tr.appendChild(tdS);
      tr.appendChild(makeCell(number(r.count),'num'));
      return tr;
    }));

    // Recent requests & errors
    await filterRequests({}, from, to);
    const errs = await jget(`/api/errors?${qp({limit:50})}`);
    renderTable($('#errorsTbl tbody'), errs, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(fmtLocal(r.ts)));
      tr.appendChild(makeCell(r.level));
      tr.appendChild(makeCell(r.pid));
      tr.appendChild(makeCell(r.tid));
      const msg = r.message.length>200 ? r.message.slice(0,200)+'…' : r.message;
      tr.appendChild(makeCell(msg));
      return tr;
     });
   }

   function toggleAutoRefresh(){
     autoRefreshEnabled = !autoRefreshEnabled;
     const button = $('#refresh');
     if (autoRefreshEnabled) {
       button.textContent = '▶️ Live';
       button.classList.remove('paused');
       button.classList.add('live');
       refreshInterval = setInterval(refresh, 10000);
     } else {
       button.textContent = '⏸️ Paused';
       button.classList.remove('live');
       button.classList.add('paused');
       if (refreshInterval) {
         clearInterval(refreshInterval);
         refreshInterval = null;
       }
     }
   }

   async function filterRequests(extra={}, fromSec=null, toSec=null){
    const preset = $('#rangePreset').value;
    let range = inferRange(preset);
    if (!range) {
      if (preset !== 'duration') alert('Select a valid range.');
      return;
    }
    const from = fromSec ?? Math.floor(range.from.getTime()/1000);
    const to = toSec ?? Math.floor(range.to.getTime()/1000);
    const base = {from, to, limit:50, offset:0, ...extra};
    const hostSel = $('#hostFilter');
    const host = hostSel ? hostSel.value : '';
    if (host) base.host = host;
    const rows = await jget(`/api/requests?${qstr(base)}`);
    renderTable($('#reqTbl tbody'), rows, r => {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(fmtLocal(r.ts)));
      tr.appendChild(makeCell(r.remote || (r.xff||'')));
      tr.appendChild(makeCell(r.method));
      tr.appendChild(makeCell(r.path));
      const tdStatus = makeCell(r.status);
      tdStatus.className = statusClass(r.status);
      tr.appendChild(tdStatus);
      tr.appendChild(makeCell(number(r.bytes),'num'));
      tr.appendChild(makeCell(r.referer || ''));
      tr.appendChild(makeCell(r.ua || ''));
      return tr;
    });
  }

  function init(){
    loadSessionInfo();
    // Restore saved UI settings
    const savedPreset = localStorage.getItem('lt_range_preset');
    const savedBucket = localStorage.getItem('lt_bucket');
    const durationInput = $('#duration');
    const savedDuration = localStorage.getItem('lt_duration');
    durationInput.value = savedDuration || '5m';
    durationInput.addEventListener('change', () => {
      const val = durationInput.value.trim();
      localStorage.setItem('lt_duration', val);
      const valid = parseGoDuration(val);
      if (!valid) {
        durationInput.classList.add('input-error');
        return;
      }
      durationInput.classList.remove('input-error');
      if ($('#rangePreset').value === 'duration') refresh();
    });
    durationInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const val = durationInput.value.trim();
        localStorage.setItem('lt_duration', val);
        const valid = parseGoDuration(val);
        if (!valid) {
          durationInput.classList.add('input-error');
          return;
        }
        durationInput.classList.remove('input-error');
        if ($('#rangePreset').value === 'duration') refresh();
      }
    });
    if (savedPreset) {
      const sel = $('#rangePreset');
      if ([...sel.options].some(o=>o.value===savedPreset)) {
        sel.value = savedPreset;
        setCustomInputsVisible(savedPreset);
      }
    }
    if (savedBucket) {
      const sel = $('#bucket');
      if ([...sel.options].some(o=>o.value===savedBucket)) sel.value = savedBucket;
    }
    setCustomInputsVisible($('#rangePreset').value);

    // Default custom inputs to last 7d for easy edits (does not override preset)
    const now = new Date(); const from7 = new Date(now.getTime()-7*86400*1000);
    setCustomFromTo({from:from7, to:now});

    $('#rangePreset').addEventListener('change', e => {
      const preset = e.target.value;
      localStorage.setItem('lt_range_preset', preset);
      setCustomInputsVisible(preset);
      if (preset === 'duration') {
        const val = $('#duration').value.trim();
        const valid = parseGoDuration(val);
        const durationInput = $('#duration');
        if (!valid) {
          if (durationInput) durationInput.classList.add('input-error');
          return;
        }
        if (durationInput) durationInput.classList.remove('input-error');
        refresh();
      } else if (preset !== 'custom') {
        refresh();
      }
    });
     $('#refresh').addEventListener('click', () => toggleAutoRefresh());
    $('#bucket').addEventListener('change', (e) => { localStorage.setItem('lt_bucket', e.target.value); refresh(); });
    const hostFilter = $('#hostFilter');
    if (hostFilter) {
      hostFilter.addEventListener('change', () => {
        refresh();
      });
    }
    window.addEventListener('resize', () => {
      // Chart.js is responsive; no heavy redraw needed. Debounce optional updates.
      clearTimeout(window.__rt); window.__rt = setTimeout(()=>{ if(reqChart) reqChart.resize(); if(errChart) errChart.resize(); if(uaFamChart) uaFamChart.resize(); if(hostsChart) hostsChart.resize(); }, 150);
    });

     refresh().then(() => {
       // Start auto-refresh after initial load
       refreshInterval = setInterval(refresh, 10000);
       // Set initial button state
       const button = $('#refresh');
       button.textContent = '▶️ Live';
       button.classList.add('live');
     }).catch(err => {
       console.error(err);
       alert('Failed to load data: '+err.message);
     });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
    

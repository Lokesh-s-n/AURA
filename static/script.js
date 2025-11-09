// static/script.js — professional AURA UI (updated tabs: Alerts | Logs | Honeypots | Blocked | Admin)

(function () {
  // small helpers
  const esc = s => (s===undefined||s===null) ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // DOM (updated names)
  const statusEl = document.getElementById('status-display');
  const blockedCountEl = document.getElementById('blocked-count');
  const honeypotCountEl = document.getElementById('honeypot-count');
  const alertsList = document.getElementById('alerts-list');
  const logsList = document.getElementById('logs-list');
  const honeypotsList = document.getElementById('honeypots-list');
  const blockedListCompact = document.getElementById('blocked-list-compact');
  const integrityList = document.getElementById('integrity-list');

  const gfLat = document.getElementById('gf-lat');
  const gfLon = document.getElementById('gf-lon');
  const gfRadius = document.getElementById('gf-radius');
  const gfSave = document.getElementById('gf-save');
  const gfReset = document.getElementById('gf-reset');
  const geoAction = document.getElementById('geo-action');

  const hpModal = document.getElementById('hp-modal');
  const hpModalTitle = document.getElementById('hp-modal-title');
  const hpModalBody = document.getElementById('hp-modal-body');
  const hpDownloadBtn = document.getElementById('hp-download-btn');
  const hpModalClose = document.getElementById('hp-modal-close');

  const adminModal = document.getElementById('admin-modal');
  const adminClose = document.getElementById('admin-close');
  const forceIntegrityBtn = document.getElementById('force-integrity');
  const viewBaselineBtn = document.getElementById('view-baseline');
  const adminUnblockInput = document.getElementById('admin-unblock-ip');
  const adminUnblockBtn = document.getElementById('admin-unblock-btn');
  const adminOutput = document.getElementById('admin-output');

  const tabAlerts = document.getElementById('tab-alerts');
  const tabLogs = document.getElementById('tab-logs');
  const tabHoneypots = document.getElementById('tab-honeypots');
  const tabBlocked = document.getElementById('tab-blocked');
  const tabAdmin = document.getElementById('tab-admin');

  // small state
  let map, userMarker;
  let recent = new Map(); // dedupe
  let geofence = { center_lat: 17.3850, center_lon: 78.4867, radius_km: 50 };
  let geofenceCircle = null;
  const geofenceMarkers = {};
  const RECENT_TTL = 9000;

  // initialize main map
  function initMap() {
    map = L.map('map', { center: [20,0], zoom: 2, worldCopyJump:true });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '&copy; OpenStreetMap' }).addTo(map);
    userMarker = L.circleMarker([geofence.center_lat, geofence.center_lon], { radius:5, color:'#00d4c4', fillColor:'#00d4c4', fillOpacity:0.9 })
      .addTo(map).bindPopup('Geofence centre (default)');
    drawGeofenceOnMap();
  }

  function drawGeofenceOnMap() {
    if (!map) return;
    if (geofenceCircle) { try { map.removeLayer(geofenceCircle); } catch(e){} geofenceCircle = null; }
    geofenceCircle = L.circle([geofence.center_lat, geofence.center_lon], {
      radius: (geofence.radius_km || 0) * 1000,
      color: '#00d4c4', weight:2, dashArray: '6', fillOpacity:0.04
    }).addTo(map);
    if (userMarker) { userMarker.setLatLng([geofence.center_lat, geofence.center_lon]); userMarker.bindPopup('Geofence centre').openPopup(); }
    map.setView([geofence.center_lat, geofence.center_lon], Math.max(3, Math.min(8, Math.round(6 - Math.log(geofence.radius_km+1)))));
  }

  // load geofence config from server
  async function loadGeofenceConfig() {
    try {
      const r = await fetch('/geofence_config'); if (!r.ok) return;
      const cfg = await r.json();
      if (!cfg) return;
      geofence.center_lat = parseFloat(cfg.center_lat) || geofence.center_lat;
      geofence.center_lon = parseFloat(cfg.center_lon) || geofence.center_lon;
      geofence.radius_km = parseFloat(cfg.radius_km) || geofence.radius_km;
      if (cfg.geo_unknown_action) { geoAction.value = cfg.geo_unknown_action; }
      gfLat.value = geofence.center_lat; gfLon.value = geofence.center_lon; gfRadius.value = geofence.radius_km;
      drawGeofenceOnMap();
    } catch (e) {
      console.warn('Failed load geofence config', e);
    }
  }

  // save geofence config
  async function saveGeofenceConfig() {
    const lat = parseFloat(gfLat.value), lon = parseFloat(gfLon.value), radius = parseFloat(gfRadius.value);
    if (Number.isNaN(lat) || Number.isNaN(lon) || Number.isNaN(radius)) {
      alert('Please enter valid numeric lat, lon and radius.');
      return;
    }
    const payload = { center_lat: lat, center_lon: lon, radius_km: radius };
    try {
      const r = await fetch('/geofence_config', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) });
      const j = await r.json();
      if (!r.ok) { alert('Failed to save geofence: ' + (j.message||r.statusText)); return; }
      geofence.center_lat = lat; geofence.center_lon = lon; geofence.radius_km = radius;
      drawGeofenceOnMap();
      gfSave.textContent = 'Saved ✓';
      setTimeout(()=> gfSave.textContent = 'Save', 1400);
    } catch (e) {
      console.error(e); alert('Network error saving geofence');
    }
  }

  // reset to default (conservative)
  function resetGeofence() {
    geofence = { center_lat: 17.3850, center_lon: 78.4867, radius_km: 50 };
    gfLat.value = geofence.center_lat; gfLon.value = geofence.center_lon; gfRadius.value = geofence.radius_km;
    drawGeofenceOnMap();
  }

  // small dedupe cleanup
  setInterval(() => {
    const now = Date.now();
    for (const [k,t] of recent) if (now - t > RECENT_TTL) recent.delete(k);
  }, 3000);

  // UI helpers: add alert or log item
  function addAlertItem(item) {
    const key = `${item.src_ip}->${item.dst_ip}@${item.external_ip}:${item.score}:${item.geofence_violation ? 'G' : 'N'}`;
    if (recent.has(key)) return; recent.set(key, Date.now());

    const el = document.createElement('div'); el.className = 'card';
    const left = document.createElement('div'); left.innerHTML = `<div><strong>${esc(item.external_ip)}</strong></div><div class="meta">${esc(item.country||'Unknown')}</div>`;
    const right = document.createElement('div'); right.style.textAlign='right';
    right.innerHTML = `<div style="font-weight:700;color:${item.score>=0.9? '#ff9a9a' : (item.score>=0.6? '#ffb86b' : '#9ef3d9') }">${(item.score||0).toFixed(2)}</div>
                       <div class="meta">${item.geofence_violation ? 'Geofence Violation' : (item.location_unknown ? 'Unknown loc' : 'Location ok')}</div>`;
    el.appendChild(left); el.appendChild(right);
    alertsList.prepend(el);
    if (alertsList.children.length > 80) alertsList.removeChild(alertsList.lastChild);
  }

  function addLogItem(item) {
    const el = document.createElement('div'); el.className = 'card';
    el.innerHTML = `<div><strong>${esc(item.external_ip||item.src_ip)}</strong><div class="meta">${esc(item.country||'Unknown')}</div></div>
                    <div style="text-align:right"><div style="font-weight:700">${(item.score||0).toFixed(2)}</div><div class="meta">${item.honeypot ? 'Honeypot' : (item.blocked ? 'Blocked' : 'OK')}</div></div>`;
    logsList.prepend(el);
    if (logsList.children.length > 200) logsList.removeChild(logsList.lastChild);
  }

  // compact blocked list render (for Blocked tab)
  async function renderBlockedCompact() {
    try {
      const r = await fetch('/blocked'); const list = await r.json();
      blockedListCompact.innerHTML = '';
      if (!Array.isArray(list) || list.length === 0) {
        blockedListCompact.innerHTML = '<div class="card"><div class="meta">No blocked IPs</div></div>';
        blockedCountEl.textContent = 0;
        return;
      }
      blockedCountEl.textContent = list.length;
      list.slice(0,200).forEach(ip => {
        const el = document.createElement('div'); el.className = 'card';
        el.innerHTML = `<div><strong>${esc(ip)}</strong></div><div class="meta">${esc(ip)}</div>`;
        blockedListCompact.appendChild(el);
      });
    } catch (e) { console.warn('renderBlockedCompact', e); }
  }

  // integrity events
  async function refreshIntegrity() {
    try {
      const r = await fetch('/integrity'); const evs = await r.json();
      if (!Array.isArray(evs) || evs.length===0) return;
      evs.forEach(ev => {
        const el = document.createElement('div'); el.className='card';
        el.innerHTML = `<div><strong>Drift</strong><div class="meta">${ev.timestamp || ''}</div></div>
                        <div class="meta">${ev.total_changes || (ev.modified||[]).length} changes</div>`;
        integrityList.prepend(el);
        if (integrityList.children.length > 40) integrityList.removeChild(integrityList.lastChild);
      });
    } catch (e) { /* ignore */ }
  }

  // honeypot listing
  async function refreshHoneypots() {
    try {
      const r = await fetch('/honeypots'); const list = await r.json();
      honeypotCountEl.textContent = Array.isArray(list) ? list.length : 0;
      honeypotsList.innerHTML = '';
      if (!Array.isArray(list) || list.length===0) {
        honeypotsList.innerHTML = '<div class="card"><div class="meta">No active honeypots</div></div>'; return;
      }
      list.forEach(hp => {
        const el = document.createElement('div'); el.className='card';
        el.innerHTML = `<div><strong>${esc(hp.attacker_ip)}</strong><div class="meta">Port: ${esc(hp.target_port)} • Logs: ${esc(hp.log_count)}</div></div>
                        <div style="text-align:right"><div class="meta">${esc(hp.started_at)}</div><div><button class="btn ghost" data-ip="${esc(hp.attacker_ip)}">View</button></div></div>`;
        honeypotsList.appendChild(el);
      });

      // add click handlers to "View" buttons
      Array.from(honeypotsList.querySelectorAll('button[data-ip]')).forEach(btn => {
        btn.addEventListener('click', (ev) => {
          const ip = ev.currentTarget.getAttribute('data-ip');
          openHpModal(ip);
        });
      });

    } catch (e) { console.warn('refreshHoneypots', e); }
  }

  // draw traffic on map + geofence micro view
  function drawConnectionOnMap(item) {
    if (!map) return;
    if (item.lat==null || item.lon==null) return;
    const dest = [item.lat, item.lon];
    const color = item.honeypot ? '#ff8a3d' : (item.score>=0.6 ? '#ff6b6b' : '#52e0b4');
    try {
      const path = L.curve(['M', [geofence.center_lat, geofence.center_lon], 'Q', [(geofence.center_lat+dest[0])/2, (geofence.center_lon+dest[1])/2], dest], { color, weight:2, opacity:0.85 }).addTo(map);
      setTimeout(()=> { try { map.removeLayer(path);} catch(e){} }, 2400);
    } catch (e) {}
  }

  function haversine(lat1,lon1,lat2,lon2){
    const R=6371; const dLat=(lat2-lat1)*Math.PI/180; const dLon=(lon2-lon1)*Math.PI/180;
    const a = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)*Math.sin(dLon/2);
    return R*2*Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  }

  function updateGeofenceMarker(item) {
    if (!map) return;
    const key = item.external_ip || item.src_ip;
    // remove old marker
    try { if (geofenceMarkers[key]) { map.removeLayer(geofenceMarkers[key]); delete geofenceMarkers[key]; } } catch(e){}
    if (item.lat==null || item.lon==null){
      // unknown location: create small red marker jitter near center
      const jitter = (Math.random()-0.5)*0.03;
      const approx = [geofence.center_lat + jitter, geofence.center_lon + jitter];
      const m = L.circleMarker(approx, { radius:8, color:'#ff6b6b', fillColor:'#ff8c8c', fillOpacity:0.95}).addTo(map);
      m.bindPopup(`<b>${esc(key)}</b><br>Location: unknown<br>Score: ${(item.score||0).toFixed(2)}`);
      geofenceMarkers[key]=m;
      return;
    }
    const dist = haversine(geofence.center_lat, geofence.center_lon, item.lat, item.lon);
    const outside = dist > (geofence.radius_km||0);
    const color = outside ? '#ff6b6b' : '#52e0b4';
    const m = L.circleMarker([item.lat, item.lon], { radius: Math.max(5, Math.min(12, 5 + (item.score||0)*6)), color, fillColor: color, fillOpacity:0.95 }).addTo(map);
    m.bindPopup(`<b>${esc(key)}</b><br>Score: ${(item.score||0).toFixed(2)}<br>Distance: ${dist.toFixed(2)} km<br>${outside?'<b style="color:#ff6b6b">Outside geofence</b>':'Inside geofence'}`);
    geofenceMarkers[key]=m;
  }

  // periodic fetch loops
  async function fetchStatus() {
    try {
      const r = await fetch('/status'); const j = await r.json();
      if (j.mode === 'Learning') statusEl.textContent = `Learning (${j.time_remaining||0}s)`;
      else statusEl.textContent = 'Monitoring';
    } catch (e) { statusEl.textContent = 'Error'; }
  }

  async function fetchTraffic() {
    try {
      const r = await fetch('/traffic'); const items = await r.json();
      if (!Array.isArray(items)) return;
      items.forEach(it => {
        // UI
        if (it.score >= 0.6) addAlertItem(it); else addLogItem(it);
        // map connection
        drawConnectionOnMap(it);
        // geofence micro-markers
        updateGeofenceMarker(it);
      });
    } catch (e) {}
  }

  async function fetchAll() {
    await fetchStatus(); await fetchTraffic(); await renderBlockedCompact(); await refreshIntegrity(); await refreshHoneypots();
  }

  // honeypot modal functions
  let hpLogs = {}; // keyed by ip
  async function fetchHoneypotLogs() {
    try {
      const r = await fetch('/honeypot_logs'); const logs = await r.json();
      if (!Array.isArray(logs)) return;
      logs.forEach(l => {
        const ip = l.attacker_ip || 'unknown';
        hpLogs[ip] = hpLogs[ip] || [];
        hpLogs[ip].push(l);
        if (hpLogs[ip].length > 500) hpLogs[ip] = hpLogs[ip].slice(-500);
      });
    } catch (e) {}
  }

  function openHpModal(ip) {
    hpModal.style.display = 'flex';
    hpModalTitle.textContent = ip;
    renderHp(ip);
  }
  function closeHpModal() {
    hpModal.style.display = 'none';
  }
  function renderHp(ip) {
    const list = hpLogs[ip] || [];
    if (!list.length) { hpModalBody.innerHTML = '<div style="color:var(--muted)">No logs yet</div>'; return; }
    let html = '';
    list.slice(-120).reverse().forEach(it => {
      html += `<div style="padding:10px;border-bottom:1px dashed rgba(255,255,255,0.02); font-family:Roboto Mono; font-size:13px;">
                 <div style="color:#9edfd7; font-weight:700">${esc(it.timestamp||'')}</div>
                 <div style="white-space:pre-wrap; color:#dbeff0; margin-top:6px">${esc(it.data||'(no payload)')}</div>
                 <div class="meta" style="color:var(--muted); margin-top:6px">${esc(it.remote_addr||'')} • port: ${esc(it.target_port||it.local_port||'N/A')}</div>
              </div>`;
    });
    hpModalBody.innerHTML = html;
  }

  // download logs
  function downloadHpLogs(ip) {
    const list = hpLogs[ip] || []; if (!list.length) { alert('No logs'); return; }
    let out = `AURA Honeypot logs for ${ip}\nGenerated: ${new Date().toLocaleString()}\n\n`;
    list.forEach((e,i) => {
      out += `#${i+1} ${e.timestamp||''}\nRemote: ${e.remote_addr||''}\nData:\n${e.data||''}\n\n----\n`;
    });
    const b = new Blob([out], { type:'text/plain' });
    const url = URL.createObjectURL(b);
    const a = document.createElement('a'); a.href = url; a.download = `honeypot_${ip.replace(/[^\w.-]/g,'_')}.txt`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }

  // Admin modal actions
  async function forceIntegrity() {
    try {
      adminOutput.textContent = 'Requesting integrity scan...';
      const r = await fetch('/force_integrity'); const j = await r.json();
      adminOutput.textContent = 'Result: ' + JSON.stringify(j);
      setTimeout(()=> adminOutput.textContent = '', 6000);
    } catch (e) { adminOutput.textContent = 'Error forcing integrity'; }
  }

  function viewBaseline() {
    // best-effort: show baseline path (we can't read file content from frontend)
    adminOutput.textContent = 'Baseline path: integrity_baseline.json (on server root)';
    setTimeout(()=> adminOutput.textContent = '', 6000);
  }

  async function adminUnblock() {
    const ip = adminUnblockInput.value.trim();
    if (!ip) { adminOutput.textContent = 'Enter IP'; return; }
    // We'll call unblock via a simple workaround: no explicit API - we try to call /blocked then ask user to remove manually.
    adminOutput.textContent = 'Please remove ' + ip + ' from blocked_ips.json on server or use firewall tools. (No direct API available)';
    setTimeout(()=> adminOutput.textContent = '', 6000);
  }

  // event listeners
  gfSave.addEventListener('click', saveGeofenceConfig);
  gfReset.addEventListener('click', resetGeofence);

  document.getElementById('refresh-blocked').addEventListener('click', renderBlockedCompact);
  hpModalClose.addEventListener('click', closeHpModal);
  hpDownloadBtn.addEventListener('click', ()=> { const ip = hpModalTitle.textContent; downloadHpLogs(ip); });

  // admin modal
  tabAdmin.addEventListener('click', ()=> {
    // activate admin tab, show modal
    [tabAlerts,tabLogs,tabHoneypots,tabBlocked].forEach(t=>t.classList.remove('active'));
    tabAdmin.classList.add('active');
    // show admin modal (center)
    adminModal.style.display = 'flex';
  });
  adminClose.addEventListener('click', ()=> { adminModal.style.display = 'none'; tabAdmin.classList.remove('active'); tabAlerts.classList.add('active'); alertsList.style.display='flex'; logsList.style.display='none'; honeypotsList.style.display='none'; blockedListCompact.style.display='none'; });
  forceIntegrityBtn.addEventListener('click', forceIntegrity);
  viewBaselineBtn.addEventListener('click', viewBaseline);
  adminUnblockBtn.addEventListener('click', adminUnblock);

  // Tab toggle behavior for activity
  function setActiveTab(active) {
    // hide all
    alertsList.style.display='none'; logsList.style.display='none'; honeypotsList.style.display='none'; blockedListCompact.style.display='none';
    [tabAlerts,tabLogs,tabHoneypots,tabBlocked,tabAdmin].forEach(t=>t.classList.remove('active'));
    if (active === 'alerts') { tabAlerts.classList.add('active'); alertsList.style.display='flex'; }
    else if (active === 'logs') { tabLogs.classList.add('active'); logsList.style.display='flex'; }
    else if (active === 'honeypots') { tabHoneypots.classList.add('active'); honeypotsList.style.display='flex'; refreshHoneypots(); }
    else if (active === 'blocked') { tabBlocked.classList.add('active'); blockedListCompact.style.display='flex'; renderBlockedCompact(); }
  }
  tabAlerts.addEventListener('click', ()=> setActiveTab('alerts'));
  tabLogs.addEventListener('click', ()=> setActiveTab('logs'));
  tabHoneypots.addEventListener('click', ()=> setActiveTab('honeypots'));
  tabBlocked.addEventListener('click', ()=> setActiveTab('blocked'));

  // initial
  window.addEventListener('load', async () => {
    initMap();
    await loadGeofenceConfig();
    // short poll loops
    fetchAll();
    setInterval(fetchStatus, 2500);
    setInterval(fetchTraffic, 1400);
    setInterval(fetchHoneypotLogs, 2600);
    setInterval(renderBlockedCompact, 6000);
    setInterval(refreshIntegrity, 8000);
    setInterval(refreshHoneypots, 7000);
    // populate honeypot logs in background
    setInterval(fetchHoneypotLogs, 4500);
    // default active tab
    setActiveTab('alerts');
  });

})();

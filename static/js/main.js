// Main JS for AtendeXportal PoC
function showToast(msg, t='info'){
  const c = document.getElementById('toast-container');
  const d = document.createElement('div'); d.className='toast'; d.textContent = msg; c.appendChild(d);
  setTimeout(()=>{ d.style.opacity=0; setTimeout(()=>d.remove(),600)}, 4000);
}

// Student: attach mark handler if present
document.addEventListener('DOMContentLoaded', ()=>{
  const markBtn = document.getElementById('markBtn');
  if(markBtn){
    markBtn.addEventListener('click', async ()=>{
      const resEl = document.getElementById('markResult'); resEl.textContent='Requesting location...';
      if(!navigator.geolocation){ resEl.textContent='Geolocation not supported'; showToast('Geolocation not supported'); return; }
      navigator.geolocation.getCurrentPosition(async (pos)=>{
        const lat = pos.coords.latitude; const lon = pos.coords.longitude;
        resEl.textContent='Got location. Sending...';
        const token = document.querySelector('.session-box').dataset.token;
        try{
          const resp = await fetch('/session/mark', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token, lat, lon})});
          // Try to parse JSON, but handle non-JSON gracefully
          let data = null;
          try { data = await resp.json(); } catch (e){ /* non-json response */ }
          if(!resp.ok){
            const msg = (data && data.message) ? data.message : (resp.statusText || 'Server error. Please try again.');
            resEl.textContent = msg;
            showToast(msg, 'warning');
            return;
          }
          resEl.textContent = data.message;
          showToast(data.message);
          if(data.grace_seconds){ startGraceTimer(data.grace_seconds); }
        }catch(e){ resEl.textContent='Error marking attendance'; showToast('Network error'); }
      }, (err)=>{ resEl.textContent='Location error: '+err.message; showToast(err.message) });
    });
  }

  // Session page init
  const live = document.getElementById('live-log');
  if(live){
    const sessionId = live.dataset.sessionId;
    function renderLive(names){
      live.innerHTML = '';
      names.forEach(n=>{ const d=document.createElement('div'); d.textContent=n; d.className='fade'; live.appendChild(d)});
    }
    async function fetchLive(){ const r=await fetch(`/session/${sessionId}/live`); const j=await r.json(); renderLive(j.names); }
    async function fetchStats(){ const r=await fetch(`/session/${sessionId}/stats`); const j=await r.json(); const ctx = document.getElementById('chart').getContext('2d'); if(window._attChart) window._attChart.destroy(); window._attChart = new Chart(ctx, {type:'bar', data:{labels:j.labels,datasets:[{label:'Attendance',data:j.counts,backgroundColor:getComputedStyle(document.documentElement).getPropertyValue('--purple')||'#5b2e8c'}]}}); }
    fetchLive(); fetchStats(); setInterval(fetchLive,3000); setInterval(fetchStats,5000);
  }
});

// Grace timer display
function startGraceTimer(seconds){
  const el = document.getElementById('graceTimer'); if(!el) return; let s = seconds;
  function tick(){ if(s<=0){ el.textContent='Grace period ended'; return; } let m = Math.floor(s/60); let sec = s%60; el.textContent = `Grace Time Remaining: ${m}:${sec.toString().padStart(2,'0')}`; s--; setTimeout(tick,1000); }
  tick();
}

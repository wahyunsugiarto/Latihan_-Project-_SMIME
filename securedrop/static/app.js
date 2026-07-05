/* ============================================================
   SecureDrop console — logika UI
   ============================================================ */
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];

// ---------- util ----------
async function api(url, opts={}){
  const r = await fetch(url, opts);
  if(r.status===401){ location.href='/login'; throw new Error('sesi habis'); }
  const ct = r.headers.get('content-type')||'';
  const data = ct.includes('json') ? await r.json().catch(()=>({})) : await r.text();
  if(!r.ok) throw new Error((data && data.detail) || 'Gagal');
  return data;
}
function jpost(url, body){ return api(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); }
function fmtBytes(n){ n=+n||0; const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return (i===0?n:n.toFixed(1))+' '+u[i]; }
function esc(s){ return (s??'').toString().replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function toast(msg, kind){ const t=document.createElement('div'); t.className='toast '+(kind||''); t.textContent=msg; $('#toasts').appendChild(t); setTimeout(()=>t.remove(),4200); }

// ---------- tema ----------
function applyTheme(t){ document.documentElement.setAttribute('data-theme',t); localStorage.setItem('sd-theme',t);
  $('#theme-icon').innerHTML = t==='dark'
    ? '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'
    : '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>'; }
function toggleTheme(){ applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'); }
applyTheme(localStorage.getItem('sd-theme')||'dark');

// ---------- navigasi ----------
const TITLES={overview:'Ikhtisar',send:'Kirim file',inbox:'Kotak masuk',history:'Riwayat keamanan',vault:'Brankas',audit:'Audit log',directory:'Direktori'};
function nav(view){
  $$('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.view===view));
  $$('.view').forEach(v=>v.classList.remove('active'));
  $('#v-'+view).classList.add('active');
  $('#view-title').textContent=TITLES[view]||'';
  $('#sidebar').classList.remove('open');
  if(view==='inbox'){ loadInbox(); loadFiles(); }
  if(view==='history') loadHistory();
  if(view==='vault'){ loadVault(); loadFiles(); }
  if(view==='audit') loadAudit();
  if(view==='directory') loadDirectory();
  if(view==='send'){ loadDirectory(); loadFiles(); }
}

// ---------- seals C/I/A/N ----------
const SEAL_ICONS={
  confidentiality:'<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  integrity:'<path d="M20 6 9 17l-5-5"/>',
  authentication:'<path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6l-8-4Z"/>',
  non_repudiation:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>'
};
const SEAL_NAMES={confidentiality:'Kerahasiaan',integrity:'Integritas',authentication:'Autentikasi',non_repudiation:'Nir-sangkal'};
function sealRow(obj){
  return `<div class="seals">`+['confidentiality','integrity','authentication','non_repudiation'].map(k=>{
    const on=!!obj[k]; const cls=on?'on':'';
    return `<div class="seal ${cls}"><div class="glyph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${SEAL_ICONS[k]}</svg></div>
      <div class="name">${SEAL_NAMES[k]}</div><div class="state">${on?'✓ aktif':'—'}</div></div>`;
  }).join('')+`</div>`;
}

// ---------- identitas ----------
async function loadIdentity(){
  try{
    const d=await api('/api/identity');
    $('#chip-user').textContent=d.username;
    $('#avatar').textContent=(d.username||'?')[0].toUpperCase();
    $('#ov-name').textContent=d.username;
    $('#ov-fp').textContent=d.fingerprint;
    $('#ov-ca').textContent=d.ca_fingerprint;
    $('#ov-expiry').textContent='berlaku s/d '+d.cert_expires;
    $('#chain-me').textContent=d.username;
    $('#ov-server').textContent=`Server: ${d.server_host}:${d.server_port} · ${d.server_ok?'terhubung':'TIDAK terhubung'}`;
    $('#server-dot').classList.toggle('off', !d.server_ok);
  }catch(e){ /* redirect handled */ }
}

// ---------- direktori ----------
let DIRECTORY=[];
async function loadDirectory(){
  try{
    DIRECTORY=await api('/api/directory');
  }catch(e){ toast('Direktori: '+e.message,'err'); return; }
  // dropdown penerima (kecuali diri sendiri)
  const sel=$('#s-to'); const cur=sel.value;
  sel.innerHTML=DIRECTORY.filter(u=>!u.me).map(u=>`<option value="${esc(u.username)}" ${u.trusted?'':'disabled'}>${esc(u.username)}${u.trusted?'':' (tak tepercaya)'}</option>`).join('')||'<option value="">(belum ada penerima lain)</option>';
  if(cur) sel.value=cur;
  // tabel
  const tb=$('#dir-table tbody');
  tb.innerHTML=DIRECTORY.map(u=>{
    const pill=u.trusted?`<span class="pill pill-ok">tepercaya via CA</span>`:`<span class="pill pill-bad">tak tepercaya</span>`;
    return `<tr><td><b style="color:var(--text)">${esc(u.username)}</b>${u.me?' <span class="pill pill-iris">anda</span>':''}</td>
      <td class="mono" style="font-size:12px">${esc(u.short)}</td><td>${pill}<div class="muted" style="font-size:11px;margin-top:3px">${esc(u.trust_reason)}</div></td></tr>`;
  }).join('');
}

// ---------- files ----------
async function loadFiles(){
  let d; try{ d=await api('/api/files'); }catch(e){ return; }
  const opt=arr=>arr.map(f=>`<option value="${esc(f.name)}">${esc(f.name)} · ${fmtBytes(f.size)}</option>`).join('');
  const sf=$('#s-file'); const cur=sf.value; sf.innerHTML=opt(d.outbox)||'<option value="">(outbox kosong)</option>'; if(cur)sf.value=cur;
  const vf=$('#vault-file'); const cv=vf.value; vf.innerHTML=opt(d.outbox)||'<option value="">(outbox kosong)</option>'; if(cv)vf.value=cv;
  // sent encrypted
  $('#sent-enc').innerHTML = d.sent_encrypted.length? d.sent_encrypted.map(f=>fileRow(f,'sent_encrypted',true)).join('') : '<div class="empty">Belum ada.</div>';
  // received (decrypted)
  $('#received-list').innerHTML = d.received.length? d.received.map(f=>fileRow(f,'received',false)).join('') : '<div class="empty">Belum ada file diterima.</div>';
}
function fileRow(f, kind, enc){
  return `<div class="file-row"><div class="file-ic">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg></div>
    <div class="file-meta"><div class="file-name">${esc(f.name)}</div><div class="file-sub">${fmtBytes(f.size)}${enc?' · terenkripsi':''}</div></div>
    <div class="file-actions"><a class="btn btn-sm" href="/api/download?kind=${kind}&name=${encodeURIComponent(f.name)}">Unduh</a></div></div>`;
}

// ---------- upload ----------
async function uploadFile(){
  const inp=$('#s-upload'); if(!inp.files.length)return;
  const fd=new FormData(); fd.append('file',inp.files[0]);
  $('#upload-state').textContent='mengunggah…';
  try{ const r=await api('/api/upload',{method:'POST',body:fd}); $('#upload-state').textContent='✓ '+r.name; await loadFiles(); $('#s-file').value=r.name; }
  catch(e){ $('#upload-state').textContent=''; toast('Unggah gagal: '+e.message,'err'); }
  inp.value='';
}

// ---------- kirim ----------
async function doSend(){
  const to=$('#s-to').value; if(!to) return toast('Pilih penerima dulu.','err');
  const path=$('#s-path').value.trim(); const filename=$('#s-file').value;
  if(!path && !filename) return toast('Pilih file dari outbox atau isi path.','err');
  try{
    const r=await jpost('/api/send',{to, filename: path?null:filename, path: path||null, note:$('#s-note').value});
    toast(r.message,'ok'); nav('overview'); startPolling();
  }catch(e){ toast('Kirim gagal: '+e.message,'err'); }
}

// ---------- inbox ----------
let INBOX=[];
async function loadInbox(){
  try{ INBOX=await api('/api/inbox'); }catch(e){ toast('Inbox: '+e.message,'err'); return; }
  const badge=$('#badge-inbox'); badge.style.display=INBOX.length?'inline-block':'none'; badge.textContent=INBOX.length;
  $('#inbox-list').innerHTML = INBOX.length? INBOX.map(inboxCard).join('') : '<div class="empty">Kotak masuk kosong.</div>';
}
function inboxCard(m){
  return `<div class="file-row" style="flex-wrap:wrap">
    <div class="file-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
    <div class="file-meta"><div class="file-name">${esc(m.filename)} <span class="pill pill-iris">dari ${esc(m.from)}</span></div>
      <div class="file-sub">${fmtBytes(m.size)} · ${esc(m.created_at)} · sha256:${esc((m.enc_sha256||'').slice(0,16))}…</div>
      ${m.note?`<div class="muted" style="font-size:12px;margin-top:3px">“${esc(m.note)}”</div>`:''}</div>
    <div class="file-actions">
      <a class="btn btn-sm btn-ghost" href="/api/download?kind=received_encrypted&name=${encodeURIComponent(m.filename+'.sdrop')}" title="unduh versi terenkripsi (bila sudah pernah diterima)">Terenkripsi</a>
      <button class="btn btn-sm btn-primary" onclick='openReceive(${JSON.stringify(m)})'>Dekripsi…</button>
    </div></div>`;
}
function openReceive(m){
  const dir=prompt(`Dekripsi "${m.filename}" ke folder mana?\n(kosongkan = folder bawaan "received")`,'');
  if(dir===null) return;
  jpost('/api/receive',{blob_id:m.blob_id, out_dir:dir.trim()||null})
    .then(r=>{ toast(r.message,'ok'); nav('overview'); startPolling(); })
    .catch(e=>toast('Terima gagal: '+e.message,'err'));
}

// ---------- progres langsung ----------
let POLL=null;
const STAGES=['encrypt','transfer','receive','verify','decrypt'];
function startPolling(){ if(POLL)return; POLL=setInterval(pollProgress,1000); pollProgress(); }
function stopPolling(){ clearInterval(POLL); POLL=null; }
async function pollProgress(){
  let snap; try{ snap=await api('/api/progress'); }catch(e){ return; }
  const items=Object.entries(snap);
  const box=$('#live-transfers');
  if(!items.length){ box.innerHTML='<div class="empty">Belum ada transfer aktif.</div>'; stopPolling(); loadFiles(); return; }
  const anyActive=items.some(([k,v])=>v.status==='active');
  box.innerHTML=items.map(([k,v])=>progCard(v)).join('');
  if(!anyActive){ stopPolling(); loadFiles(); loadInbox(); loadHistory(); }
}
function progCard(v){
  const dir=v.direction==='out'?'Mengirim':'Menerima';
  const pct=v.percent||0;
  const statusPill=v.status==='done'?'<span class="pill pill-ok">selesai</span>':v.status==='error'?'<span class="pill pill-bad">gagal</span>':'<span class="pill pill-iris">berjalan</span>';
  const curStage=v.stage||'';
  const stages=STAGES.map(s=>{
    let cls=''; const idx=STAGES.indexOf(s), ci=STAGES.indexOf(curStage);
    if(v.status==='error'&&s===curStage) cls='err';
    else if(v.status==='done'||idx<ci) cls='done';
    else if(s===curStage) cls='active';
    // untuk arah keluar, tahap receive/decrypt tak berlaku
    const na=(v.direction==='out'&&(s==='receive'||s==='decrypt'))||(v.direction==='in'&&s==='encrypt');
    return `<div class="stg ${na?'':cls}" style="${na?'opacity:.35':''}">${s}</div>`;
  }).join('');
  const cian=(v.status==='done'&&v.direction==='in')?`<div style="margin-top:12px">${sealRow({confidentiality:true,integrity:v.integrity,authentication:v.authenticated,non_repudiation:v.signature})}</div>`:'';
  return `<div style="padding:14px 0;border-bottom:1px solid var(--border)">
    <div class="row"><b style="color:var(--text)">${dir}: ${esc(v.filename||'…')}</b>${v.peer?`<span class="muted">${v.direction==='out'?'→':'←'} ${esc(v.peer)}</span>`:''}<div class="sp"></div>${statusPill}</div>
    <div class="prog"><div class="prog-bar"><div class="prog-fill" style="width:${pct}%"></div></div>
      <div class="prog-meta"><span>${pct}%</span><span>${fmtBytes(v.done||0)}/${fmtBytes(v.total||0)}</span><span>⇅ ${esc(v.speed||'-')}</span><span>⏱ ${v.elapsed||0}s berjalan</span>${v.total_time?`<span>total ${v.total_time}s</span>`:''}${v.error?`<span style="color:var(--rose)">${esc(v.error)}</span>`:''}</div>
      <div class="prog-stages">${stages}</div>${cian}</div></div>`;
}
function clearProgress(){ jpost('/api/progress/clear').then(pollProgress); }

// ---------- riwayat keamanan ----------
async function loadHistory(){
  let list; try{ list=await api('/api/transfers'); }catch(e){ return; }
  const box=$('#history-list');
  if(!list.length){ box.innerHTML='<div class="empty">Belum ada riwayat.</div>'; return; }
  box.innerHTML=list.map(t=>{
    const dir=t.direction==='out'?`ke ${esc(t.receiver)}`:t.direction==='in'?`dari ${esc(t.sender)}`:'';
    const arrow=t.direction==='out'?'↗':'↙';
    const tl=t.stages.map(s=>`<li class="${s.status==='error'?'err':'done'}"><span class="tl-dot"></span>
      <div class="tl-body"><div class="row"><span class="tl-stage">${esc(s.stage||'—')}</span><div class="sp"></div><span class="tl-time">${esc(s.timestamp)}</span></div>
      <div class="tl-res">${esc(s.result||s.error||'')}</div></div></li>`).join('');
    return `<div class="card" style="margin-bottom:16px"><div class="card-pad">
      <div class="row"><span class="pill pill-iris">${arrow} ${t.direction==='out'?'kirim':'terima'}</span>
        <b style="color:var(--text)">${esc(t.filename||'(tanpa nama)')}</b><span class="muted">${dir} · ${fmtBytes(t.size)}</span>
        <div class="sp"></div><span class="muted mono" style="font-size:11px">${esc(t.last)}</span></div>
      <div style="margin:14px 0">${sealRow(t)}</div>
      ${t.verify_result?`<div class="hint" style="margin-bottom:8px">Verifikasi: ${esc(t.verify_result)}</div>`:''}
      <ul class="tl">${tl}</ul></div></div>`;
  }).join('');
}

// ---------- brankas ----------
async function loadVault(){
  let d; try{ d=await api('/api/vault'); }catch(e){ return; }
  $('#vault-out-hint').textContent='Bawaan: '+d.default_out;
  $('#vault-list').innerHTML = d.files.length? d.files.map(f=>`<div class="file-row">
    <div class="file-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
    <div class="file-meta"><div class="file-name">${esc(f.name)}</div><div class="file-sub">${fmtBytes(f.size)}</div></div>
    <div class="file-actions"><button class="btn btn-sm btn-primary" onclick="vaultDecrypt('${esc(f.name)}')">Buka</button></div></div>`).join('')
    : '<div class="empty">Brankas kosong.</div>';
}
async function vaultEncrypt(){
  const name=$('#vault-file').value; if(!name) return toast('Pilih file dari outbox.','err');
  try{ const r=await jpost('/api/vault/encrypt',{filename:name}); toast('Terenkripsi ke brankas: '+r.file,'ok'); loadVault(); loadHistory(); }
  catch(e){ toast('Gagal: '+e.message,'err'); }
}
async function vaultDecrypt(name){
  const out=$('#vault-out').value.trim();
  try{
    const r=await jpost('/api/vault/decrypt',{name, out_dir:out||null});
    toast(`Dibuka: ${r.filename} → ${r.out_path}`,'ok');
    loadHistory();
  }catch(e){ toast('Gagal membuka: '+e.message,'err'); }
}

// ---------- audit ----------
async function loadAudit(){
  let d; try{ d=await api('/api/audit'); }catch(e){ return; }
  const rows=d.local||[];
  const tb=$('#audit-table tbody');
  if(!rows.length){ tb.innerHTML='<tr><td colspan="8" class="empty">Belum ada catatan.</td></tr>'; return; }
  tb.innerHTML=rows.map(e=>{
    const st=e.status==='ok'?'pill-ok':e.status==='error'?'pill-bad':'pill-idle';
    const cian=['confidentiality','integrity','authentication','non_repudiation'].map(k=>e[k]?'<span style="color:var(--emerald)">●</span>':'<span class="muted">○</span>').join(' ');
    const fromTo=(e.sender||'-')+'→'+(e.receiver||'-');
    return `<tr><td class="mono" style="font-size:12px">${esc(e.timestamp)}</td><td>${esc(e.stage||'-')}</td>
      <td><span class="pill ${st}">${esc(e.status||'-')}</span></td><td class="mono" style="font-size:12px">${esc(fromTo)}</td>
      <td>${esc(e.filename||'-')}</td><td class="mono" style="font-size:12px">${e.size?fmtBytes(e.size):'-'}</td>
      <td style="white-space:nowrap">${cian}</td><td class="muted" style="font-size:12px">${esc(e.result||e.error||'')}</td></tr>`;
  }).join('');
}
async function clearAudit(){ if(!confirm('Kosongkan audit log lokal?'))return;
  try{ await api('/api/audit',{method:'DELETE'}); loadAudit(); toast('Audit log dikosongkan.','ok'); }catch(e){ toast(e.message,'err'); } }

// ---------- logout ----------
async function doLogout(){ try{ await jpost('/api/logout'); }catch(e){} location.href='/login'; }

// ---------- init ----------
(async function(){
  await loadIdentity();
  await loadDirectory();
  await loadFiles();
  await loadInbox();
  // jika ada progres tersisa, mulai polling
  try{ const snap=await api('/api/progress'); if(Object.keys(snap).length) startPolling(); }catch(e){}
  setInterval(loadInbox, 15000);
})();

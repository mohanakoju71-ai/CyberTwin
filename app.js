'use strict';
/* ---------- tiny safe templating: interpolations are HTML-escaped unless produced by h`` ---------- */
class Raw{constructor(s){this.s=s}}
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const part=v=>v instanceof Raw?v.s:Array.isArray(v)?v.map(part).join(''):esc(v);
const h=(s,...v)=>new Raw(s.reduce((a,x,i)=>a+x+(i<v.length?part(v[i]):''),''));
const $=s=>document.querySelector(s);
const NAV=[
 {id:'home',label:'Home',icon:'M3 11l9-8 9 8M5 10v10h14V10',pages:[['home','Overview'],['dashboard','Detailed dashboard']]},
 {id:'twin',label:'My Digital Twin',icon:'M12 2l9 5v10l-9 5-9-5V7zM12 12l9-5M12 12L3 7M12 12v10',pages:[['twin','My Digital Twin'],['behavior','Normal behavior']]},
 {id:'activity',label:'Security Activity',icon:'M3 12h4l3-8 4 16 3-8h4',pages:[['events','All events'],['live','Live feed'],['submit','Add a sample event']]},
 {id:'alerts',label:'Risks and Alerts',icon:'M12 3l10 18H2zM12 10v5M12 18v.5',pages:[['threats','Alerts'],['risk','Risk score'],['xai','Why it was flagged']]},
 {id:'devices',label:'Devices and Networks',icon:'M3 5h18v11H3zM8 20h8M12 16v4',pages:[['devices','Devices'],['network','Networks']]},
 {id:'investigate',label:'AI Security Assistant',icon:'M4 4h16v12H9l-5 4z',pages:[['investigate','Ask the assistant']]},
 {id:'response',label:'Protection Actions',icon:'M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z',pages:[['response','Actions and history']]},
 {id:'reports',label:'Reports',icon:'M6 2h9l5 5v15H6zM14 2v6h6M9 13h8M9 17h8',pages:[['reports','Reports']]},
 {id:'settings',label:'Settings',icon:'M4 6h16M4 12h16M4 18h16M9 4v4M15 10v4M8 16v4',pages:[['settings','Settings']]}];
const SEVCOL={Critical:'#F43F5E',High:'#FB923C',Medium:'#FBBF24',Low:'#34D399',None:'#8A97AD'};
let TWIN=null,CFG={medium:30,high:60,critical:85,refresh_seconds:5},timer=null,online=true,Q={q:'',sev:'',sort:'ts',order:'desc'},SEL=null;

/* ---------- API ---------- */
async function api(path,opt={}){
  let r;
  const ac=new AbortController(),tt=setTimeout(()=>ac.abort(),12000);
  try{r=await fetch('/api'+path,{method:opt.method||'GET',headers:opt.body?{'Content-Type':'application/json'}:{},body:opt.body?JSON.stringify(opt.body):undefined,signal:ac.signal});}
  catch(e){setOnline(false);throw new Error(e.name==='AbortError'?'The server took too long to answer.':'Cannot reach the CyberTwin server. Is it running?');}
  finally{clearTimeout(tt)}
  setOnline(true);
  const type=r.headers.get('content-type')||'';
  const data=type.includes('json')?await r.json():await r.text();
  if(!r.ok)throw new Error(typeof data==='object'?(data.detail||'Request failed'):'Request failed ('+r.status+')');
  return data;
}
function setOnline(v){online=v;$('#offline').hidden=v;$('#conn').innerHTML=`<i class="dot" style="background:${v?'var(--ok)':'var(--cr)'}"></i><span class="lbl">${v?'API connected':'API offline'}</span>`}
function toast(m,t=''){const d=document.createElement('div');d.className='toast '+t;d.textContent=m;$('#toasts').append(d);setTimeout(()=>d.remove(),5000)}
const ago=iso=>{if(!iso)return 'never';const s=(Date.now()-new Date(iso))/1000;return s<60?Math.round(s)+'s ago':s<3600?Math.round(s/60)+' min ago':s<86400?Math.round(s/3600)+' h ago':Math.round(s/86400)+' d ago'};
const tm=iso=>iso?new Date(iso).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'-';
const badge=s=>h`<span class="badge" style="color:${SEVCOL[s]||'#8A97AD'}">${s}</span>`;
const scol=v=>v>=CFG.critical?SEVCOL.Critical:v>=CFG.high?SEVCOL.High:v>=CFG.medium?SEVCOL.Medium:SEVCOL.Low;
const bar=(l,v,max=100,suffix='%',color)=>h`<div class="row" style="margin:9px 0"><span style="width:170px">${l}</span><div class="bar"><i style="--w:${Math.min(100,Math.max(0,v/max*100))}%;${color?'background:'+color:''}"></i></div><b style="min-width:42px;text-align:right">${v}${suffix}</b></div>`;
const skeleton=h`<div class="skel"></div><div class="skel" style="height:220px"></div><div class="skel"></div>`;
const empty=(t,a='')=>h`<div class="empty">${t}${a?h`<br><br>${a}`:''}</div>`;

/* ---------- dialogs ---------- */
function dialog(content){const m=$('#modal'),prev=document.activeElement;m.hidden=false;m.innerHTML=`<div role="dialog" aria-modal="true" tabindex="-1">${content.s}</div>`;
  const close=()=>{m.hidden=true;m.innerHTML='';prev&&prev.focus&&prev.focus()};m._close=close;const f=m.querySelector('button,input,select');(f||m.firstChild).focus();return close}
function confirmDlg(title,body,{danger=false,typed=null,ok='Confirm'}={}){return new Promise(res=>{
  const close=dialog(h`<h2>${title}</h2><p class="mu">${body}</p>${typed?h`<input id="typed" aria-label="Type ${typed} to confirm" placeholder='Type "${typed}"' style="width:100%;margin-bottom:12px">`:''}<div class="row"><button class="btn ${danger?'d':''}" id="y">${ok}</button><button class="btn g" id="n">Cancel</button></div>`);
  $('#n').onclick=()=>{close();res(false)};$('#y').onclick=()=>{if(typed&&$('#typed').value!==typed){toast('Type '+typed+' exactly to continue','err');return}close();res(true)}})}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#modal').hidden)$('#modal')._close()});
$('#modal').addEventListener('click',e=>{if(e.target.id==='modal')$('#modal')._close()});

/* ---------- charts ---------- */
function trendChart(pts,w=640,hh=200){if(!pts.length)return empty('No data');const n=pts.length,P=pts.map((p,i)=>[14+i*(w-28)/Math.max(1,n-1),hh-24-p.max/100*(hh-40)]);
  const s=P.map(a=>a.join(',')).join(' ');
  return h`<svg viewBox="0 0 ${w} ${hh}" width="100%" role="img" aria-label="Risk trend, highest event score per bucket"><defs><linearGradient id="lg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38BDF8" stop-opacity=".35"/><stop offset="1" stop-color="#38BDF8" stop-opacity="0"/></linearGradient></defs>
  ${[CFG.medium,CFG.high,CFG.critical].map(t=>h`<line x1="0" x2="${w}" y1="${hh-24-t/100*(hh-40)}" y2="${hh-24-t/100*(hh-40)}" stroke="#334155" stroke-dasharray="3 5"/><text x="${w-4}" y="${hh-27-t/100*(hh-40)}" text-anchor="end" fill="#64748b" font-size="10">${t}</text>`)}
  <polygon points="14,${hh-24} ${s} ${w-14},${hh-24}" fill="url(#lg)"/><polyline points="${s}" fill="none" stroke="#38BDF8" stroke-width="2.5"/>
  ${P.map((a,i)=>h`<circle cx="${a[0]}" cy="${a[1]}" r="3.5" fill="${scol(pts[i].max)}"><title>${pts[i].label}: max ${pts[i].max}, ${pts[i].count} events</title></circle>`)}
  ${pts.map((p,i)=>(n<=8||i%4===0)?h`<text x="${P[i][0]}" y="${hh-6}" text-anchor="middle" fill="#64748b" font-size="10">${p.label}</text>`:'')}</svg>`}
const ring=(v,l,sz=120)=>{const r=sz/2-10,c=2*Math.PI*r;return h`<svg width="${sz}" height="${sz}" role="img" aria-label="${l}: ${v} of 100"><circle cx="${sz/2}" cy="${sz/2}" r="${r}" fill="none" stroke="#1E293B" stroke-width="9"/><circle cx="${sz/2}" cy="${sz/2}" r="${r}" fill="none" stroke="${scol(v)}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${c*v/100} ${c}" transform="rotate(-90 ${sz/2} ${sz/2})" style="transition:stroke-dasharray .8s"/><text x="50%" y="${sz*.6}" text-anchor="middle" fill="#fff" font-family="Sora" font-size="${sz/4}" font-weight="700">${v}</text></svg>`};

/* ---------- reusable fragments ---------- */
const evRows=(items,cols=true)=>items.length?h`<div style="overflow:auto"><table><tr><th>Time<th>Event<th>Device<th>Network<th>Score<th>Severity<th>Incident</tr>${items.map(e=>h`<tr class="click" tabindex="0" data-act="finding" data-arg="${e.id}"><td>${tm(e.ts)}<td>${e.event_type.replace('_',' ')}<td>${e.device}<td>${e.network}<td><b style="color:${scol(e.score)}">${e.score}</b><td>${badge(e.severity)}<td>${e.incident_status||'-'}</tr>`)}</table></div>`:empty('No events yet.',h`<button class="btn" data-act="scenario" data-arg="unknown_device">Run a scenario</button>`);
const actTable=a=>a.length?h`<div style="overflow:auto"><table><tr><th>Time<th>Action<th>Target<th>Status<th>What actually happened</tr>${a.map(x=>h`<tr><td>${tm(x.ts)}<td>${x.label}<td>${x.target}<td><span class="badge ${x.mode==='simulated'?'Medium':'Low'}">${x.status}</span><td>${x.result}</tr>`)}</table></div>`:empty('No response actions recorded yet.');
const contribList=c=>c.length?c.map(x=>h`<div style="margin:10px 0"><div class="row sp"><span>${x.factor} <span class="chip">${x.kind}</span></span><b style="color:${x.points<0?'var(--ok)':'var(--tx)'}">${x.points>0?'+':''}${x.points}</b></div><div class="bar"><i style="--w:${Math.min(100,Math.abs(x.points)*3)}%;${x.points<0?'background:var(--ok)':''}"></i></div><div class="mu" style="font-size:12px">${x.detail}</div></div>`):h`<p class="mu">No contributing factors; the event matches the learned baseline.</p>`;
const scenarioPicker=async()=>{const sc=await api('/scenarios');return h`<select id="sc" aria-label="Scenario">${sc.map(s=>h`<option value="${s.key}" title="${s.description}">${s.title}</option>`)}</select> <button class="btn" data-act="runsel">Run scenario</button>`};

/* ---------- pages ---------- */

const STC={trusted:'#34D399',unfamiliar:'#FBBF24',suspicious:'#F43F5E'};
function twinSvg(d,mini){const W=800,H=mini?340:460,cx=W/2,cy=H/2,pos={user:[cx,cy]};
 const arc=(arr,a0,a1)=>arr.forEach((n,i)=>{const a=a0+(a1-a0)*(arr.length===1?.5:i/(arr.length-1));pos[n.id]=[cx+300*Math.cos(a),cy+H*.36*Math.sin(a)]});
 const dev=d.nodes.filter(n=>n.type==='device'),net=d.nodes.filter(n=>n.type==='network');arc(dev,Math.PI*.68,Math.PI*1.32);arc(net,-.34*Math.PI,.34*Math.PI);
 d.events.forEach((e,k)=>{const b=pos['d'+e.device_id];if(b)pos['e'+e.id]=[Math.max(34,b[0]-64),Math.min(H-24,Math.max(24,b[1]+(k%2?44:-44)))]});
 const node=(n)=>{const p=pos[n.id];if(!p)return '';const c=n.type==='user'?'#38BDF8':STC[n.status],r=n.type==='user'?42:(mini?22:27);
  return h`<g tabindex="0" role="button" class="tn" data-act="node" data-arg="${n.id}" aria-label="${n.type} ${n.label}: ${n.plain}"><title>${n.plain}</title>${n.status==='suspicious'?h`<circle class="pulse" cx="${p[0]}" cy="${p[1]}" r="${r+6}" fill="none" stroke="${c}"/>`:''}<circle cx="${p[0]}" cy="${p[1]}" r="${r}" fill="#0C1424" stroke="${c}" stroke-width="2.5"/><text x="${p[0]}" y="${p[1]+4}" text-anchor="middle" fill="${n.type==='user'?'#fff':'#94a3b8'}" font-size="${n.type==='user'?13:10}">${n.type==='user'?'Twin':n.type==='device'?'device':'network'}</text><text x="${p[0]}" y="${p[1]+r+15}" text-anchor="middle" fill="#e2e8f0" font-size="${mini?10:11.5}">${n.label.length>20?n.label.slice(0,19)+'…':n.label}</text></g>`};
 return h`<svg viewBox="0 0 ${W} ${H}" width="100%" role="group" aria-label="Digital twin graph. Every node is focusable; a table with the same data follows."><defs><radialGradient id="tg"><stop offset="0" stop-color="#38BDF8" stop-opacity=".25"/><stop offset="1" stop-color="#38BDF8" stop-opacity="0"/></radialGradient></defs><circle cx="${cx}" cy="${cy}" r="${H*.5}" fill="url(#tg)"/>
 ${d.edges.filter(e=>pos[e.from]&&pos[e.to]).map(e=>h`<line class="flowline" x1="${pos[e.from][0]}" y1="${pos[e.from][1]}" x2="${pos[e.to][0]}" y2="${pos[e.to][1]}" stroke="#38BDF8" stroke-opacity="${e.count?Math.min(.7,.2+e.count/90):.25}" stroke-width="${1+Math.min(3,e.count/25)}"/>`)}
 ${d.events.filter(e=>pos['e'+e.id]&&pos['d'+e.device_id]).map(e=>h`<line x1="${pos['d'+e.device_id][0]}" y1="${pos['d'+e.device_id][1]}" x2="${pos['e'+e.id][0]}" y2="${pos['e'+e.id][1]}" stroke="${SEVCOL[e.severity]}" stroke-dasharray="3 4" stroke-opacity=".7"/>`)}
 ${d.nodes.map(node)}
 ${d.events.filter(e=>pos['e'+e.id]).map(e=>{const p=pos['e'+e.id],c=SEVCOL[e.severity];return h`<g tabindex="0" role="button" class="tn" data-act="node" data-arg="e${e.id}" aria-label="Event ${e.id}, ${e.severity}: ${e.plain}"><title>${e.plain}</title><rect x="${p[0]-11}" y="${p[1]-11}" width="22" height="22" transform="rotate(45 ${p[0]} ${p[1]})" fill="#0C1424" stroke="${c}" stroke-width="2"/><text x="${p[0]}" y="${p[1]+4}" text-anchor="middle" fill="${c}" font-size="10" font-weight="700">!</text></g>`})}</svg>`}
const PAGES={
async dashboard(){const s=await api('/state');CFG=s.settings;const r=s.risk,t=s.totals,b=s.baseline;
 return h`<section class="hero"><div><h1>Detailed dashboard</h1><p>Risk priority: <b style="color:${SEVCOL[r.severity]}">${r.severity==='None'?'No open incidents':r.severity}</b> · ${r.basis} · server time ${tm(s.server_time)}</p></div><div class="row wrap">${await scenarioPicker()}</div></section>
 <p class="note">Demo mode: every event shown here is synthetic. No operating system, browser or physical network is being monitored.</p><br>
 <div class="grid g4">
  <div class="card row">${ring(r.score,'Risk priority')}<div><div class="mu">Risk priority</div><b>${r.severity==='None'?'-':r.severity}</b></div></div>
  <div class="card"><div class="mu">Open incidents</div><div class="big">${t.open_incidents}</div><div class="mu">${s.incidents_by_severity.Critical} critical · ${s.incidents_by_severity.High} high · ${s.incidents_by_severity.Medium} medium</div></div>
  <div class="card"><div class="mu">Events / suspicious</div><div class="big">${t.events} <small class="mu">/ ${t.suspicious}</small></div><div class="mu">suspicious = score ≥ ${CFG.medium}</div></div>
  <div class="card"><div class="mu">Devices</div><div class="big">${t.devices_trusted} <small class="mu">trusted</small></div><div class="mu">${t.devices_untrusted} untrusted</div></div></div>
 <div class="grid g32"><div class="card"><h2>Risk trend <span class="row"><button class="btn g sm" data-act="trend" data-arg="24">24 h</button><button class="btn g sm" data-act="trend" data-arg="7">7 d</button></span></h2><div id="trend">${trendChart(s.trend_24h)}</div><p class="mu" style="font-size:12px">Highest event score per bucket (scenario/API events only).</p></div>
  <div class="card"><h2>Twin baseline</h2>${bar('Baseline events',Math.min(b.n,b.min_events*2),b.min_events*2,'')}<p>Model: <b>${b.model_trained?'Isolation Forest trained':'not trained'}</b> (${b.model_samples} samples)</p><p class="mu">Usual hour (UTC): ${b.mean_hour==null?'n/a':b.mean_hour.toFixed(1)}. Status: <b>${b.ready?'ready':'insufficient data'}</b></p></div></div>
 <div class="grid g32"><div class="card"><h2>Recent events</h2>${evRows(s.recent_events)}</div>
  <div class="card"><h2>Top risk contributors</h2>${s.top_contributors.length?s.top_contributors.map(c=>bar(c.factor,c.points,Math.max(...s.top_contributors.map(x=>x.points)),' pts')):empty('No suspicious events yet.')}</div></div>
 <div class="grid g2"><div class="card"><h2>Data sources</h2><table><tr><th>Source<th>Type<th>Events<th>Last event</tr>${s.sources.map(x=>h`<tr><td>${x.name}<td><span class="chip">${x.kind}</span><td>${x.events}<td>${ago(x.last_event)}</tr>`)}</table></div>
  <div class="card"><h2>Recent response actions</h2>${actTable(s.recent_actions)}</div></div>`},


async home(){const [st,tw]=await Promise.all([api('/state'),api('/twin')]);CFG=st.settings;TWIN=tw;const r=st.risk,S=tw.summary,u=S.latest_unusual;
 const mood=r.severity==='None'||r.severity==='Low'?['Nothing unusual needs your attention right now.','ok']:r.severity==='Medium'?['One item needs a quick review.','warn']:['Something unusual should be reviewed soon.','warn'];
 const top=st.recent_events.filter(e=>e.score>=CFG.medium)[0];
 return h`<section class="hero"><div><h1>Welcome back</h1><p>Your <b>digital twin</b> is a simple model of your sign-in habits that notices when something looks different.</p></div><div class="row wrap"><a class="btn" href="#/twin">Explore my Digital Twin</a><button class="btn g" data-act="guide">Guided demo</button><button class="btn g" data-act="welcome">What is this?</button></div></section>
 <div class="grid g32"><div class="card"><h2>Your twin at a glance <span class="chip">${S.origins.user_submitted?'demo + your samples':'demonstration data'}</span></h2>${twinSvg(tw,true)}<p class="mu">Green = familiar, amber = not yet familiar, red = involved in unusual activity. Select a node to learn more.</p><div id="nodeinfo" class="mu" aria-live="polite"></div></div>
  <div><div class="card status ${mood[1]}"><h2>Overall status</h2><p class="big" style="font-size:20px">${mood[0]}</p><p class="mu">${S.learning?S.learning_message:'Based on '+st.totals.events+' stored events. Score = triage priority, not proof of a problem.'}</p></div>
  <div class="card" style="margin-top:16px"><h2>Most important item</h2>${top?h`<p>${top.device} on ${top.network} at ${tm(top.ts)} looked different from your usual pattern: ${top.contributors.filter(c=>c.points>0).map(c=>c.factor.toLowerCase()).join(', ')}.</p><p><b>Suggested next step:</b> check whether this was you.</p><div class="row wrap"><button class="btn" data-act="finding" data-arg="${top.id}">Review it</button></div>`:h`<p>No alerts yet. Run a demo scenario to see how your twin reacts.</p><button class="btn" data-act="scenario" data-arg="unknown_device">Try a demo scenario</button>`}</div></div></div>
 <div class="card"><h2>Recent important activity</h2>${evRows(st.recent_events.slice(0,5))}</div>`},

async twin(){const tw=await api('/twin');TWIN=tw;const S=tw.summary,u=S.latest_unusual,b=tw.baseline,mx=Math.max(1,...b.hist);
 const org=S.baseline_user_events?`${S.baseline_demo_events} demonstration and ${S.baseline_user_events} user-submitted`:`${S.baseline_demo_events} demonstration`;
 const q=(t,open,body)=>h`<details class="q" ${open?'open':''}><summary>${t}</summary><div>${body}</div></details>`;
 return h`<section class="hero" style="background-image:linear-gradient(90deg,rgba(7,11,20,.92),rgba(7,11,20,.35)),url(assets/bg-twin.svg)"><div><h1>My Digital Twin</h1><p>A simple, continuously updated model of your digital security behavior. It only knows what is listed on this page.</p></div><span class="pill">${tw.profile.synthetic?'Demonstration data':'Demo + your submitted samples'}</span></section>
 ${S.learning?h`<p class="note">${S.learning_message}</p><br>`:''}
 <div class="grid g32"><div class="card twinbox"><h2>Your twin and what it is connected to</h2>${twinSvg(tw,false)}<div class="row wrap legend"><span class="chip" style="color:#34D399">● familiar</span><span class="chip" style="color:#FBBF24">● not yet familiar</span><span class="chip" style="color:#F43F5E">● unusual activity</span><span class="chip">◆ security event</span></div><div id="nodeinfo" class="note" style="margin-top:10px;background:rgba(56,189,248,.08);border-color:rgba(56,189,248,.3);color:var(--tx)" aria-live="polite">Select a device, network or event to see what it means.</div></div>
 <div class="card"><h2>In plain words</h2><ul class="plain"><li>Your twin has learned from <b>${S.learned_events}</b> events (${org}).</li><li><b>${S.devices}</b> devices and <b>${S.networks}</b> networks are represented.</li><li>${S.open_incidents?`<b>${S.open_incidents}</b> item(s) need review.`:'Nothing currently needs review.'}</li>${u?h`<li>The latest unusual activity: ${u.reasons.map(r=>r.toLowerCase()).join(', ')}.</li><li>Next step: ${u.verify}</li>`:''}</ul>${bar('Learning progress',Math.min(100,Math.round(S.learned_events/CFG.baseline_min_events*100)))}<div class="row wrap"><a class="btn sm" href="#/submit">Add a sample event</a><button class="btn g sm" data-act="guide">Guided demo</button></div></div></div>
 <div class="card"><h2>Questions your twin can answer</h2>
 ${q('What does my twin know about my digital activity?',true,h`<p>It knows ${S.learned_events} sign-in events used as your baseline, plus ${tw.nodes.length-1} devices and networks seen in stored events. Data origin: ${S.origins.demonstration} demonstration event(s) and ${S.origins.user_submitted} user-submitted. It does <b>not</b> read your real accounts, files, browser or network.</p>`)}
 ${q('Which devices and networks are represented?',false,h`<div style="overflow:auto"><table><tr><th>Type<th>Name<th>Status<th>Events</tr>${tw.nodes.filter(n=>n.type!=='user').map(n=>h`<tr><td>${n.type}<td>${n.label}<td>${{trusted:'familiar',unfamiliar:'not yet familiar',suspicious:'unusual activity'}[n.status]}<td>${n.count}</tr>`)}</table></div>`)}
 ${q('What does my normal behavior look like?',false,S.usual_hour_utc==null?h`<p>Not enough data yet.</p>`:h`<p>You usually sign in around <b>${S.usual_hour_utc}:00 UTC</b> (within ±${S.time_window_hours} h), from your trusted devices and familiar networks.</p><svg viewBox="0 0 480 90" width="100%" role="img" aria-label="Sign-in hours">${b.hist.map((v,i)=>h`<rect x="${i*20}" y="${70-v/mx*60}" width="16" height="${v/mx*60}" rx="3" fill="#38BDF8" opacity=".85"><title>${i}:00 — ${v}</title></rect><text x="${i*20+8}" y="85" text-anchor="middle" fill="#64748b" font-size="8">${i}</text>`)}</svg>`)}
 ${q('Has anything unusual happened?',!!u,u?h`<p>Yes: ${u.device} on ${u.network} at ${tm(u.ts)} (${u.severity}, priority score ${u.score}/100). <button class="btn g sm" data-act="finding" data-arg="${u.id}">Open details</button></p>`:h`<p>No unusual activity is stored. Run a demo scenario to see how your twin reacts.</p>`)}
 ${q('Why is it considered unusual?',!!u,u?h`<ul>${u.reasons.map(r=>h`<li>${r}</li>`)}</ul>${u.benign_signals.length?h`<p>Signals that point to normal behavior: ${u.benign_signals.join(', ')}.</p>`:''}<p class="mu"><b>What is uncertain:</b> ${u.uncertainty}</p><details class="tech"><summary>Technical details</summary><p>Method: ${u.method}. Confidence: ${u.confidence}. Data origin: ${u.origin}. ${u.explanation}</p></details>`:h`<p>Nothing to explain yet.</p>`)}
 ${q('What is my current risk, and what should I do next?',!!u,u?h`<p>Priority score <b style="color:${scol(u.score)}">${u.score}/100 (${u.severity})</b>. This ranks what to look at first; it is not the chance that something is wrong.</p><p><b>What to verify:</b> ${u.verify}</p><p><b>Suggested:</b> ${u.recommended.join(', ')||'keep monitoring'} <a href="#/response">Open Protection Actions</a></p>`:h`<p>Your current priority is low; keep monitoring.</p>`)}
 ${q('How does my twin improve when I give feedback?',false,h`<p>When you mark an event as <b>expected</b>, it may be added to your baseline and the model is retrained. Marking it <b>suspicious</b> never teaches the twin that it is normal. High-priority events and events with repeated failed sign-ins are never added automatically, and feedback can supply at most 20% of the baseline.</p><p>So far: ${S.feedback.total} review(s), ${S.feedback.expected} expected, ${S.feedback.suspicious} suspicious, ${S.feedback.added_to_baseline} event(s) added to the baseline.</p>`)}</div>
 <div class="card"><h2>What CyberTwin can and cannot see</h2><div class="grid g2" style="margin:0"><div><b>Can use</b><ul><li>Demonstration events built into the app</li><li>Sample events you type in yourself</li></ul></div><div><b>Cannot access</b><ul><li>Your passwords, one-time codes or recovery codes</li><li>Gmail, WhatsApp, banking, social accounts</li><li>Your computer, browser history or real network</li></ul></div></div><p class="mu">Protective actions here are simulated or local records. They do not change any real account or device.</p></div>`},

async submit(){const [dv,nw]=await Promise.all([api('/devices'),api('/networks')]);const now=new Date(Date.now()-new Date().getTimezoneOffset()*60000).toISOString().slice(0,16);
 return h`<div class="grid g2"><form class="card" id="sample"><h2>Add a sample sign-in event</h2><p class="mu">Type an event yourself. It is labelled <b>user-submitted</b> and is not captured from your devices. Passwords and codes must never be entered.</p>
 <label>Device<input name="device" list="dl" required maxlength="80" placeholder="e.g. Personal Laptop"></label><datalist id="dl">${dv.items.map(d=>h`<option value="${d.name}">`)}</datalist>
 <label>Network<input name="network" list="nl" required maxlength="80" placeholder="e.g. Home Wi-Fi"></label><datalist id="nl">${nw.items.map(n=>h`<option value="${n.name}">`)}</datalist>
 <label>When (your local time)<input type="datetime-local" name="when" value="${now}" max="${now}" required></label>
 <label>Failed attempts before this sign-in<input type="number" name="failed" min="0" max="50" value="0"></label>
 <label class="row"><input type="checkbox" name="success" checked> The sign-in succeeded</label><label class="row"><input type="checkbox" name="mfa"> Extra verification (MFA) was completed</label>
 <button class="btn" id="sbtn" style="margin-top:10px">Score this event</button></form><div class="card" id="sres"><h2>Result</h2>${empty('Submit an event to see how your twin judges it.')}</div></div>`},

async live(){return h`<div class="card"><h2>Live feed <span id="lstat" class="pill">connecting…</span></h2><div class="row wrap" id="lmeta" class="mu"></div><div id="lfeed"></div></div>`},

async threats(){return h`<div class="card"><h2>Alerts</h2>${filters(true)}<div id="tbl">${skeleton}</div></div>`},
async events(){return h`<div class="card"><h2>Security events</h2>${filters(false)}<div id="tbl">${skeleton}</div></div>`},

async risk(){const [s,d]=await Promise.all([api('/state'),api('/detections?limit=100')]);CFG=s.settings;const sev={Critical:0,High:0,Medium:0};d.items.forEach(e=>sev[e.severity]++);
 return h`<div class="grid g2"><div class="card" style="text-align:center"><h2>Current risk priority</h2>${ring(s.risk.score,'Risk priority',170)}<div><b style="color:${SEVCOL[s.risk.severity]}">${s.risk.severity}</b></div><p class="mu">${s.risk.basis}. A score ranks triage priority; it is not the probability of compromise.</p></div>
 <div class="card"><h2>Risk contributors (all findings)</h2>${s.top_contributors.length?s.top_contributors.map(c=>bar(c.factor,c.points,Math.max(...s.top_contributors.map(x=>x.points)),' pts')):empty('No findings yet.')}</div></div>
 <div class="grid g2"><div class="card"><h2>Findings by severity</h2>${Object.entries(sev).map(([k,v])=>bar(k,v,Math.max(1,...Object.values(sev)),'',SEVCOL[k]))}</div>
 <div class="card"><h2>7-day trend</h2>${trendChart(s.trend_7d)}</div></div>
 <div class="card"><h2>How the score is calculated</h2><p>Score = clamp(Σ factor points, 0, 100). Rules add fixed points (unknown device +30, new network +15, unusual time up to +25, failed attempts up to +20, success after failures +15). Isolation Forest adds up to +15 when its relative anomaly measure exceeds 0.2. Verified MFA on a trusted device subtracts 15. Thresholds: Medium ≥ ${CFG.medium}, High ≥ ${CFG.high}, Critical ≥ ${CFG.critical} (editable in Settings).</p></div>`},

async behavior(){const [s,d]=await Promise.all([api('/state'),api('/detections?limit=20')]);const b=s.baseline,mx=Math.max(1,...b.hist),cur=d.items[0];
 return h`<div class="grid g2"><div class="card"><h2>Login-hour baseline (UTC)</h2><svg viewBox="0 0 480 170" width="100%" role="img" aria-label="Histogram of baseline login hours">${b.hist.map((v,i)=>h`<rect x="${i*20}" y="${140-v/mx*110}" width="16" height="${v/mx*110}" rx="3" fill="#38BDF8" opacity=".85"><title>${i}:00 — ${v} events</title></rect><text x="${i*20+8}" y="156" text-anchor="middle" fill="#64748b" font-size="8">${i}</text>`)}
 ${d.items.slice(0,8).map(e=>{const hr=new Date(e.ts).getUTCHours();return h`<circle cx="${hr*20+8}" cy="12" r="5" fill="${scol(e.score)}"><title>${e.event_type} score ${e.score} at ${hr}:00</title></circle>`})}</svg><p class="mu" style="font-size:12px">Bars: baseline events (${b.n}). Dots: recent flagged findings.</p></div>
 <div class="card"><h2>Normal vs current${cur?h` <span class="chip">event #${cur.id}</span>`:''}</h2>${cur?h`<table><tr><th><th>Baseline<th>Current</tr>
  <tr><td>Time<td>${b.mean_hour==null?'n/a':b.mean_hour.toFixed(1)+'h ±'+CFG.time_window_hours}<td>${new Date(cur.ts).getUTCHours()}:00 UTC
  <tr><td>Device<td>trusted set<td>${cur.device} (${cur.device_known?'trusted':'untrusted'})<tr><td>Network<td>trusted/known<td>${cur.network} (${cur.network_known?'known':'new'})
  <tr><td>Failed attempts<td>0–1<td>${cur.failed_attempts}</tr></table><p class="mu">Model features (fixed order): ${Object.entries(cur.features).map(([k,v])=>k+'='+v).join(', ')}</p>`:empty('Run a scenario to compare against the baseline.')}</div></div>`},

async devices(){const d=await api('/devices');return h`<div class="grid g4">${d.items.map(x=>h`<div class="card"><h2>${x.name} <span class="badge ${x.trust==='trusted'?'Low':'High'}">${x.trust}</span></h2><div class="mu">${x.os} · ${x.kind}<br>Last seen ${ago(x.last_seen)}<br>${x.event_count} events · max score ${x.max_score}</div>${x.isolated_sim?h`<p class="note">Isolated in simulation only</p>`:''}<div class="row wrap" style="margin-top:10px">${x.trust==='trusted'?h`<button class="btn d sm" data-act="dtrust" data-arg="${x.id}|untrusted|${x.name}">Mark untrusted</button>`:h`<button class="btn sm" data-act="dtrust" data-arg="${x.id}|trusted|${x.name}">Mark trusted</button>`}</div></div>`)}</div><p class="mu">Trust changes update the local demo database only; no real device is modified.</p>`},

async network(){const d=await api('/networks');return h`<div class="grid g2">${d.items.map(n=>h`<div class="card"><h2>${n.name} <span class="chip">${n.trust}</span></h2><div class="mu">First seen ${tm(n.first_seen)} · last seen ${ago(n.last_seen)}</div>${bar('Events',n.event_count,Math.max(...d.items.map(x=>x.event_count)),'')}${bar('Max score',n.max_score)}<div class="row wrap">${['trusted','known','untrusted'].filter(t=>t!==n.trust).map(t=>h`<button class="btn g sm" data-act="ntrust" data-arg="${n.id}|${t}|${n.name}">Set ${t}</button>`)}</div></div>`)}</div>`},

async investigate(){const d=await api('/detections?limit=30');SEL=SEL||(d.items[0]&&d.items[0].id);
 return h`<div class="grid g32"><div class="card"><h2>AI Security Assistant</h2><label>Finding<select id="isel">${d.items.map(e=>h`<option value="${e.id}" ${e.id==SEL?'selected':''}>#${e.id} ${e.severity} – ${e.device} (${tm(e.ts)})</option>`)}</select></label>
 <div class="chat" id="ch" aria-live="polite"><div class="msg ai">Ask about the selected alert or your recent activity. Answers use only data stored in this app and say what is uncertain.</div></div>
 <div class="row wrap" style="margin:10px 0">${['Why was this sign-in flagged?','What does this risk score mean?','Could this activity be normal?','What should I do next?','Summarize my recent security activity.'].map(q=>h`<button class="btn g sm" data-act="ask" data-arg="${q}">${q}</button>`)}</div>
 <form class="row" id="qf"><input id="q" style="flex:1" maxlength="500" aria-label="Question" placeholder="Ask CyberTwin"><button class="btn">Send</button></form></div>
 <div class="card"><h2>Evidence panel</h2><div id="ev" class="mu">Ask a question to load evidence.</div></div></div>`},

async xai(){const d=await api('/detections?limit=30');if(!d.items.length)return h`<div class="card">${empty('No findings to explain yet.',h`<button class="btn" data-act="scenario" data-arg="multi_signal">Run multi-signal scenario</button>`)}</div>`;
 SEL=SEL||d.items[0].id;const e=await api('/events/'+SEL);
 return h`<div class="card"><h2>Why was this activity flagged? <select id="xsel" aria-label="Finding">${d.items.map(x=>h`<option value="${x.id}" ${x.id==SEL?'selected':''}>#${x.id} ${x.severity} ${x.score}</option>`)}</select></h2>
 <div class="row wrap">${ring(e.score,'Score',130)}<div><b class="big">${e.score}/100</b><div>${badge(e.severity)} <span class="chip">${e.method}</span> <span class="chip">confidence: ${e.confidence}</span></div></div></div><br>${contribList(e.contributors)}
 <p style="border-left:3px solid var(--cy);padding-left:12px">${e.explanation}</p><p class="mu"><b>Uncertainty:</b> ${e.uncertainty}</p>
 <div class="chain"><b>Evidence</b>→<b>Rules + model</b>→<b>Score ${e.score}</b>→<b>${e.recommended_labels.join(', ')||'Monitor'}</b></div>
 <p class="mu" style="font-size:12px">Model features: ${Object.entries(e.features).map(([k,v])=>k+'='+v).join(', ')}. The Isolation Forest value is a relative anomaly measure, not a probability. No SHAP is used.</p></div>`},

async response(){const [s,a,inc]=await Promise.all([api('/state'),api('/response/actions'),api('/incidents')]);CFG=s.settings;const open=inc.items.filter(i=>['open','investigating','confirmed'].includes(i.status));
 return h`<div class="grid g2"><div class="card"><h2>Policy <span class="pill"><i class="dot"></i>Confirmation required</span></h2>${[['< '+CFG.medium,'Monitor only'],[CFG.medium+'–'+(CFG.high-1),'Record security alert'],[CFG.high+'–'+(CFG.critical-1),'Request additional verification (simulated)'],['≥ '+CFG.critical,'Simulate session revocation / device isolation']].map(r=>h`<div class="tg"><span>Score ${r[0]}</span><b>→ ${r[1]}</b></div>`)}<p class="note">Only "Record alert" and "Mark untrusted" change local demo data. Everything else is a simulation and contacts no real system.</p></div>
 <div class="card"><h2>Open incidents (${open.length})</h2>${open.length?open.map(i=>h`<div style="padding:10px 0;border-bottom:1px solid var(--line)"><div class="row sp"><span>${badge(i.severity)} #${i.id} ${i.title}</span><button class="btn g sm" data-act="finding" data-arg="${i.event_id}">Review</button></div><div class="row wrap" style="margin-top:8px">${i.recommended.map((k,ix)=>h`<button class="btn sm" data-act="exec" data-arg="${i.id}|${k}">${a.catalog.find(c=>c.key===k).label}</button>`)}</div></div>`):empty('No open incidents.')}</div></div>
 <div class="card"><h2>Action history</h2>${actTable(a.items)}</div>`},

async reports(){const r=await api('/reports/summary');return h`<div class="grid g2"><div class="card"><h2>Report preview</h2><p>Generated ${tm(r.generated_at)} · ${r.summary.totals.events} events · ${r.summary.totals.suspicious} suspicious · ${r.incidents.length} incidents · ${r.actions.length} actions.</p><div class="row wrap"><a class="btn" href="/api/reports/events.csv" download>Download CSV</a><a class="btn g" href="/api/reports/report.html" target="_blank" rel="noopener">Open printable report</a><a class="btn g" href="/api/reports/summary" target="_blank" rel="noopener">View JSON</a></div><p class="mu">Use the printable report's “Print / Save as PDF” button for a PDF. Native PDF generation is not implemented.</p></div>
 <div class="card"><h2>Latest incidents</h2>${r.incidents.slice(0,6).map(i=>h`<div class="tg"><span>${badge(i.severity)} #${i.id} ${i.device}</span><span>${i.status}</span></div>`)||''}${r.incidents.length?'':empty('No incidents yet.')}</div></div>`},

async settings(){const [s,hl]=await Promise.all([api('/settings'),api('/health')]);const f=(k,l,min,max)=>h`<label>${l}<input type="number" name="${k}" min="${min}" max="${max}" value="${s[k]}" required></label>`;
 return h`<div class="grid g2"><form class="card" id="sf"><h2>Detection &amp; display</h2><div class="grid g2" style="margin:0">${f('medium','Medium threshold',1,99)}${f('high','High threshold',2,100)}${f('critical','Critical threshold',3,100)}${f('baseline_min_events','Min baseline events',10,500)}${f('time_window_hours','Usual-time window (± h)',1,12)}${f('refresh_seconds','Refresh interval (s)',2,60)}</div><label class="row" style="margin:12px 0"><input type="checkbox" name="demo_mode" ${s.demo_mode?'checked':''}> Demo mode</label><button class="btn">Save settings</button></form>
 <div class="card"><h2>System</h2><div class="tg"><span>Database</span><b>${hl.database}</b></div><div class="tg"><span>Isolation Forest</span><b>${hl.model_trained?'trained':'not trained'}</b></div><div class="tg"><span>Claude API (backend only)</span><b>${hl.claude_configured?'configured':'not configured – using deterministic fallback'}</b></div><div class="tg"><span>Data sources</span><b>Synthetic only</b></div><div class="row wrap" style="margin-top:12px"><button class="btn g" data-act="retrain">Retrain model</button><button class="btn d" data-act="reset">Reset demo data</button></div></div></div>`}
};

function filters(onlyFindings){return h`<div class="row wrap" style="margin-bottom:12px"><input id="fq" type="search" placeholder="Search device, network, IP, text" aria-label="Search" value="${Q.q}"><select id="fsev" aria-label="Severity"><option value="">All severities</option>${['Critical','High','Medium','Low'].filter(x=>!onlyFindings||x!=='Low').map(x=>h`<option ${Q.sev===x?'selected':''}>${x}</option>`)}</select><span class="mu">Click a column header to sort.</span></div>`}
async function loadTable(kind){const el=$('#tbl');if(!el)return;try{const p=new URLSearchParams({q:Q.q,severity:Q.sev,sort:Q.sort,order:Q.order,limit:25,offset:Q.offset||0});const d=await api((kind==='threats'?'/detections?':'/events?')+p);
 if(kind==='threats'){p.delete('sort');p.delete('order');}
 el.innerHTML=(d.items.length?h`<div style="overflow:auto"><table><tr><th data-act="sort" data-arg="ts">Time ${Q.sort==='ts'?(Q.order==='desc'?'▼':'▲'):''}<th>Finding<th>Method<th data-act="sort" data-arg="score">Score ${Q.sort==='score'?(Q.order==='desc'?'▼':'▲'):''}<th>Severity<th>Device<th>Status<th>Next step</tr>${d.items.map(e=>h`<tr class="click" tabindex="0" data-act="finding" data-arg="${e.id}"><td>${tm(e.ts)}<td>${e.event_type.replace('_',' ')} · ${e.network}<td>${e.method}<td><b style="color:${scol(e.score)}">${e.score}</b><td>${badge(e.severity)}<td>${e.device}<td>${e.incident_status||'-'}<td>${e.recommended_labels[0]||'Monitor'}</tr>`)}</table></div><div class="row sp"><span class="mu">${d.total} result(s) · showing ${(Q.offset||0)+1}–${(Q.offset||0)+d.items.length}</span><span class="row"><button class="btn g sm" data-act="page" data-arg="-1" ${(Q.offset||0)?'':'disabled'}>Previous</button><button class="btn g sm" data-act="page" data-arg="1" ${(Q.offset||0)+d.items.length<d.total?'':'disabled'}>Next</button></span></div>`:empty('No matching results.')).s}catch(e){el.innerHTML=`<div class="err">${esc(e.message)}</div>`}}

/* ---------- finding drawer ---------- */
async function openFinding(id){try{const e=await api('/events/'+id);SEL=e.id;
 const close=dialog(h`<h2>Event #${e.id} ${badge(e.severity)} <b style="color:${scol(e.score)}">${e.score}/100</b></h2><p class="mu">${tm(e.ts)} · ${e.event_type} · ${e.device} · ${e.network} ${e.ip?'· '+e.ip:''} · source ${e.source}${e.synthetic?' (synthetic)':''}</p>
 <p>${e.explanation}</p><h3 style="margin:10px 0">Risk contributors</h3>${contribList(e.contributors)}<p class="mu"><b>Uncertainty:</b> ${e.uncertainty}</p>
 <p><b>Method:</b> ${e.method} · <b>Confidence:</b> ${e.confidence} · <b>Incident:</b> ${e.incident_id?'#'+e.incident_id+' ('+e.incident_status+')':'none'}</p>
 <p><b>Recommended:</b> ${e.recommended_labels.join(', ')||'Monitor only'}</p>
 ${e.incident_id?h`<div class="row wrap">${e.recommended.map(k=>h`<button class="btn sm" data-act="exec" data-arg="${e.incident_id}|${k}" data-close="1">${e.recommended_labels[e.recommended.indexOf(k)]}</button>`)}</div>`:''}
 <h3 style="margin:14px 0 6px">Review feedback</h3><div class="row wrap"><select id="fv" aria-label="Verdict"><option value="true_positive">True positive</option><option value="false_positive">False positive</option><option value="benign_expected">Benign / expected</option></select><input id="fn" maxlength="500" placeholder="Note (optional)" style="flex:1" aria-label="Note"><button class="btn sm" id="fsave">Save feedback</button></div>
 ${e.feedback.length?h`<p class="mu">Previous: ${e.feedback.map(f=>f.verdict+(f.note?' ('+f.note+')':'')).join('; ')}</p>`:''}
 ${e.actions.length?h`<h3 style="margin:14px 0 6px">Actions</h3>${actTable(e.actions)}`:''}<div class="row" style="margin-top:14px"><button class="btn g" id="fclose">Close</button> <a class="btn g" href="#/xai" id="fx">Open in Explainable AI</a></div>`);
 $('#fclose').onclick=close;$('#fx').onclick=close;
 $('#fsave').onclick=async()=>{try{const r=await api('/feedback',{method:'POST',body:{event_id:e.id,verdict:$('#fv').value,note:$('#fn').value}});toast('Feedback saved'+(r.added_to_baseline?' and added to the baseline; model retrained':''),'ok');close();route()}catch(x){toast(x.message,'err')}}
}catch(x){toast(x.message,'err')}}

/* ---------- actions ---------- */
const ACT={
 async runsel(){return ACT.scenario($('#sc').value)},
 async scenario(k){try{const e=await api(`/scenarios/${k}/run`,{method:'POST'});SEL=e.severity==='Low'?SEL:e.id;toast(`Scenario ran: score ${e.score} (${e.severity})`,'ok');await route();if(guideOn())guideRefresh()}catch(x){toast(x.message,'err')}},
 finding:openFinding,
 trend(n,el){$('#trend').innerHTML=''; api('/state').then(s=>{$('#trend').innerHTML=trendChart(n==='24'?s.trend_24h:s.trend_7d).s})},
 node(id){const el=$('#nodeinfo');if(!el||!TWIN)return;if(id[0]==='e'&&!isNaN(+id.slice(1))){const e=TWIN.events.find(x=>x.id===+id.slice(1));if(e)el.innerHTML=`<b>Security event #${e.id} (${esc(e.severity)})</b><br>${esc(e.plain)} <br><button class="btn sm" style="margin-top:8px" data-act="finding" data-arg="${e.id}">Open details</button>`;return}
  const n=TWIN.nodes.find(x=>x.id===id);if(n)el.innerHTML=`<b>${esc(n.label)}</b> — ${{trusted:'familiar',unfamiliar:'not yet familiar',suspicious:'involved in unusual activity'}[n.status]}<br>${esc(n.plain)}${n.last_seen?' Last seen '+ago(n.last_seen)+'.':''}${n.type==='device'||n.type==='network'?` <a href="#/${n.type==='device'?'devices':'network'}">Manage</a>`:''}`},
 welcome(){welcome()},
 page(dir){Q.offset=Math.max(0,(Q.offset||0)+25*+dir);loadTable(location.hash.slice(2))},
 sort(k){Q.offset=0;Q.order=Q.sort===k&&Q.order==='desc'?'asc':'desc';Q.sort=k;loadTable(location.hash.slice(2))},
 async dtrust(a){const [id,t,n]=a.split('|');if(!await confirmDlg(`Mark ${n} ${t}?`,'This changes the local demo record only.',{danger:t==='untrusted'}))return;try{await api(`/devices/${id}/trust`,{method:'POST',body:{trust:t,confirm:true}});toast('Device updated','ok');route()}catch(x){toast(x.message,'err')}},
 async ntrust(a){const [id,t,n]=a.split('|');if(!await confirmDlg(`Set ${n} to ${t}?`,'Future events on this network will be scored accordingly.'))return;try{await api(`/networks/${id}/trust`,{method:'POST',body:{trust:t,confirm:true}});toast('Network updated','ok');route()}catch(x){toast(x.message,'err')}},
 async exec(a,el){const [iid,k]=a.split('|');const sim=!['record_alert','mark_untrusted'].includes(k);
  if(!await confirmDlg('Confirm response action',`${k.replace('_',' ')} on incident #${iid}. ${sim?'This is a SIMULATION: no real system is contacted.':'This only changes the local demo database.'}`,{danger:['revoke_session','isolate_device'].includes(k)}))return;
  try{const r=await api('/response/execute',{method:'POST',body:{incident_id:+iid,action:k,confirm:true}});toast(r.result,'ok');if(el&&el.dataset.close)$('#modal')._close();await route();if(guideOn())guideRefresh()}catch(x){toast(x.message,'err')}},
 async ask(q){const c=$('#ch');if(!c||!q)return;c.insertAdjacentHTML('beforeend',`<div class="msg me">${esc(q)}</div>`);try{const r=await api('/investigate',{method:'POST',body:{question:q,event_id:+$('#isel').value||null}});
  c.insertAdjacentHTML('beforeend',`<div class="msg ai">${esc(r.answer)}<div class="mu" style="font-size:11px;margin-top:6px">Mode: ${r.mode==='claude'?'Claude (backend)':'deterministic evidence-based fallback'}</div></div>`);c.scrollTop=1e9;
  $('#ev').innerHTML=Object.entries(r.evidence).map(([k,v])=>`<div class="tg"><span class="mu">${esc(k)}</span><b style="text-align:right">${esc(v)}</b></div>`).join('')}catch(x){c.insertAdjacentHTML('beforeend',`<div class="msg ai err">${esc(x.message)}</div>`)}},
 async retrain(){try{const r=await api('/model/retrain',{method:'POST'});toast(r.trained?`Model trained on ${r.samples} events`:'Not enough baseline events to train','ok');route()}catch(x){toast(x.message,'err')}},
 async reset(){if(!await confirmDlg('Reset all demo data?','This deletes events, incidents, actions and feedback and re-seeds the synthetic baseline.',{danger:true,typed:'RESET',ok:'Reset'}))return;try{await api('/admin/reset',{method:'POST',body:{confirm:'RESET'}});toast('Demo data reset','ok');route()}catch(x){toast(x.message,'err')}},
 guide(){guideStart()},
 retry(){retries=0;route()}
};
document.addEventListener('click',e=>{const t=e.target.closest('[data-act]');if(t&&ACT[t.dataset.act]){e.preventDefault();ACT[t.dataset.act](t.dataset.arg,t)}});
document.addEventListener('keydown',e=>{if(e.key==='Enter'){const t=e.target.closest('tr[data-act]');if(t)ACT[t.dataset.act](t.dataset.arg,t)}});
let deb;document.addEventListener('input',e=>{if(e.target.id==='fq'){clearTimeout(deb);deb=setTimeout(()=>{Q.q=e.target.value;Q.offset=0;loadTable(location.hash.slice(2))},250)}});
document.addEventListener('change',e=>{const id=e.target.id;if(id==='fsev'){Q.sev=e.target.value;Q.offset=0;loadTable(location.hash.slice(2))}if(id==='xsel'){SEL=+e.target.value;route()}if(id==='isel')SEL=+e.target.value});
document.addEventListener('submit',async e=>{if(e.target.id==='sample'){e.preventDefault();const f=new FormData(e.target),btn=$('#sbtn');if(btn.disabled)return;btn.disabled=true;
  try{const e2=await api('/ingest',{method:'POST',body:{user:'aarav',event_type:'login',device:f.get('device').trim(),network:f.get('network').trim(),failed_attempts:+f.get('failed')||0,success:!!f.get('success'),mfa_verified:!!f.get('mfa'),timestamp:new Date(f.get('when')).toISOString(),source:'user-form',synthetic:false}});
   $('#sres').innerHTML=h`<h2>Result</h2><p>Priority score <b style="color:${scol(e2.score)}">${e2.score}/100 (${e2.severity})</b> · origin: user-submitted</p><p>${e2.explanation}</p>${contribList(e2.contributors)}<p class="mu">${e2.uncertainty}</p><button class="btn" data-act="finding" data-arg="${e2.id}">Open details</button> <a class="btn g" href="#/twin">Back to my twin</a>`.s;toast('Event scored and saved','ok')}
  catch(x){toast(x.message,'err')}finally{btn.disabled=false}return}if(e.target.id==='qf'){e.preventDefault();const q=$('#q');ACT.ask(q.value);q.value=''}
 if(e.target.id==='sf'){e.preventDefault();const f=new FormData(e.target),b={demo_mode:!!f.get('demo_mode')};for(const k of ['medium','high','critical','baseline_min_events','time_window_hours','refresh_seconds'])b[k]=+f.get(k);
  try{CFG=await api('/settings',{method:'PUT',body:b});toast('Settings saved','ok')}catch(x){toast(x.message,'err')}}});

/* ---------- live ---------- */
function startLive(){let maxId=0,items=[];const tick=async()=>{try{const d=await api('/live?after_id=0');maxId=d.max_id;CFG.refresh_seconds=d.refresh_seconds;const el=$('#lfeed');if(!el)return;
  $('#lstat').innerHTML=d.stale?'<span class="warn">stale – no recent events</span>':'<span class="ok">fresh</span>';
  $('#lmeta').innerHTML=`<span class="chip">connection: ${online?'connected':'offline'}</span><span class="chip">latest event: ${d.latest_event_time?ago(d.latest_event_time):'none'}</span><span class="chip">source: ${esc(d.source)}</span><span class="chip">polling every ${d.refresh_seconds}s</span>`;
  el.innerHTML=d.items.length?evRows(d.items).s:empty('No scenario or API events yet. Events appear here when you run a scenario or POST to /api/ingest.').s}catch(x){const s=$('#lstat');if(s)s.innerHTML='<span class="err">offline</span>'}};
  tick();timer=setInterval(tick,Math.max(2,CFG.refresh_seconds)*1000)}

/* ---------- guided demo ---------- */
const STEPS=[
['#/home','1. Welcome','A digital twin is a simple model of your sign-in habits. It learns what is normal and points out what looks different.',()=>welcome()],
['#/twin','2. What it can and cannot see','Scroll to “What CyberTwin can and cannot see”. It never touches your real accounts, passwords or devices.'],
['#/twin','3. Use the demo profile','A clearly labelled demonstration profile is already loaded. (You can also add your own sample events under Security Activity.)',()=>api('/demo/prepare',{method:'POST'}).catch(()=>{})],
['#/twin','4. Baseline learned','Open “What does my twin know?” to see how many events built the baseline and what normal looks like.'],
['#/devices','5. Devices and networks','These are the devices and networks the twin represents, with their trust state.'],
['#/twin','6. A suspicious demo event arrives','Running “new network + other evidence” through the real detection pipeline…',()=>ACT.scenario('multi_signal')],
['#/xai','7. Why is it different?','Compare the event with the baseline: each reason and its points are listed.'],
['#/risk','8. Score, factors and uncertainty','The score is a triage priority. Read the uncertainty note before deciding.'],
['#/threats','9. Mark it expected or suspicious','Use “Review feedback” in the opened alert. “Suspicious” never teaches the twin it is normal.',()=>SEL&&openFinding(SEL)],
['#/twin','10. Feedback history updated','Open “How does my twin improve?” to see the updated counts.'],
['#/response','11. Recommended next action','Choose a recommended action and confirm. It is simulated or a local record and is labelled so.'],
['#/reports','12. Generate a report','Download the CSV or open the printable report (save as PDF from the browser).']];
let gi=+(sessionStorage.gi||0);const guideOn=()=>!$('#guide').hidden;
function guideRefresh(){const g=$('#guide'),s=STEPS[gi];g.hidden=false;g.innerHTML=h`<div class="row sp"><b>Step ${gi+1} of ${STEPS.length}: ${s[1]}</b><button class="btn g sm" id="gx" aria-label="Close guide">✕</button></div><p class="mu">${s[2]}</p><div class="row"><button class="btn g sm" id="gb" ${gi?'':'disabled'}>Back</button><button class="btn sm" id="gn">${gi===STEPS.length-1?'Finish':'Next'}</button></div>`.s;
 $('#gx').onclick=()=>{g.hidden=true};$('#gb').onclick=()=>guideGo(gi-1);$('#gn').onclick=()=>gi===STEPS.length-1?(g.hidden=true,sessionStorage.gi=0):guideGo(gi+1)}
async function guideGo(i){gi=i;sessionStorage.gi=i;const s=STEPS[i];guideRefresh();if(location.hash!==s[0])location.hash=s[0];else await route();if(s[3])await s[3]()}
function guideStart(){guideGo(0)}

/* ---------- welcome ---------- */
function welcome(mark=true){try{if(mark)localStorage.ct_welcomed='1'}catch(e){}const close=dialog(h`<h2>Welcome to CyberTwin</h2><p>A <b>digital twin</b> is a simple, continuously updated model of your digital security behavior: which devices and networks you normally use, and when you normally sign in.</p><p><b>What it can use:</b> demonstration events built into this app, and sample events you type in.<br><b>What it cannot access:</b> your passwords or codes, your email, WhatsApp or bank accounts, your computer or your network.</p><p class="mu">Protective actions are simulated or recorded locally. Scores are priorities to review, not proof of a problem.</p><div class="row wrap"><button class="btn" id="wg">Take the guided demo</button><button class="btn g" id="wc">Explore on my own</button></div>`);
 $('#wc').onclick=close;$('#wg').onclick=()=>{close();guideStart()}}
function welcomeOnce(){try{if(!localStorage.ct_welcomed)welcome()}catch(e){}}

/* ---------- router ---------- */
let routeSeq=0,retries=0,busy=false;
async function route(){clearInterval(timer);const seq=++routeSeq,id=location.hash.replace('#/','')||'home';
 const grp=NAV.find(g=>g.pages.some(p=>p[0]===id))||NAV[0],page=grp.pages.some(p=>p[0]===id)?id:grp.pages[0][0];
 $('#nav').innerHTML=NAV.map(g=>`<a href="#/${g.pages[0][0]}" class="${g===grp?'on':''}" ${g===grp?'aria-current="page"':''} title="${g.label}"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${g.icon}"/></svg><span>${g.label}</span></a>`).join('');
 const label=grp.pages.find(p=>p[0]===page)[1];$('#ttl').textContent=grp.label==='Home'||grp.pages.length===1?grp.label:grp.label+' · '+label;document.title='CyberTwin – '+$('#ttl').textContent;document.body.classList.remove('mopen');
 const tabs=grp.pages.length>1?h`<div class="tabs" role="navigation" aria-label="${grp.label} sections">${grp.pages.map(p=>h`<a href="#/${p[0]}" class="tab ${p[0]===page?'on':''}" ${p[0]===page?'aria-current="page"':''}>${p[1]}</a>`)}</div>`.s:'';
 const m=$('#main');m.innerHTML=tabs+skeleton.s;
 try{const out=await PAGES[page]();if(seq!==routeSeq)return;m.innerHTML=tabs+out.s;retries=0;
  if(page==='threats'||page==='events')loadTable(page);if(page==='live')startLive();
  if(page==='home'&&!window._welcomed){window._welcomed=1;welcomeOnce()}
  if(page==='home'||page==='dashboard')timer=setInterval(async()=>{if(busy||document.hidden||!online||!$('#modal').hidden)return;busy=true;try{const x=await PAGES[page]();if(seq===routeSeq)m.innerHTML=tabs+x.s}catch(e){}finally{busy=false}},Math.max(10,CFG.refresh_seconds*3)*1000)}
 catch(e){if(seq!==routeSeq)return;const wait=!online&&retries<5;
  m.innerHTML=tabs+h`<div class="card"><h2>${wait?'Waiting for the CyberTwin server…':'Could not load this page'}</h2><p class="err">${e.message}</p>${wait?h`<p class="mu">Retrying automatically (${retries+1} of 5). If this keeps failing, check that the server window is still open and see Troubleshooting in the README.</p>`:''}<button class="btn" data-act="retry">Try again</button></div>`.s;
  if(wait){retries++;setTimeout(()=>{if(seq===routeSeq)route()},3000)}}}
window.addEventListener('hashchange',route);
$('#tog').onclick=()=>innerWidth<900?document.body.classList.toggle('mopen'):$('#app').classList.toggle('collapsed');
setInterval(()=>api('/health').catch(()=>{}),8000);

/* ---------- animated background (canvas; static when reduced motion) ---------- */
(function(){const c=$('#bg'),x=c.getContext('2d'),rm=matchMedia('(prefers-reduced-motion: reduce)').matches;let W,H,N=[];
 const size=()=>{W=c.width=innerWidth;H=c.height=innerHeight;N=Array.from({length:Math.min(55,Math.round(W*H/30000))},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.25,vy:(Math.random()-.5)*.25}))};
 const draw=()=>{x.clearRect(0,0,W,H);for(const a of N){a.x=(a.x+a.vx+W)%W;a.y=(a.y+a.vy+H)%H}
  for(let i=0;i<N.length;i++){for(let j=i+1;j<N.length;j++){const d=Math.hypot(N[i].x-N[j].x,N[i].y-N[j].y);if(d<150){x.strokeStyle=`rgba(56,189,248,${.16*(1-d/150)})`;x.beginPath();x.moveTo(N[i].x,N[i].y);x.lineTo(N[j].x,N[j].y);x.stroke()}}x.fillStyle='rgba(139,92,246,.6)';x.beginPath();x.arc(N[i].x,N[i].y,1.8,0,7);x.fill()}
  if(!rm&&!document.hidden)requestAnimationFrame(draw)};
 size();addEventListener('resize',()=>{size();if(rm)draw()});document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!rm)draw()});draw()})();

api('/settings').then(s=>{CFG=s}).catch(()=>{}).finally(route);

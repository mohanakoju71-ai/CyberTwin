// Optional browser-like smoke test (jsdom). Usage: cd tests && npm i jsdom && BASE=http://127.0.0.1:8000 node ui_smoke.js
const {JSDOM,VirtualConsole}=require('jsdom');const fs=require('fs'),path=require('path');
const base=process.env.BASE||'http://127.0.0.1:8000',errs=[],fe=path.join(__dirname,'..','frontend');
const vc=new VirtualConsole();vc.on('jsdomError',e=>{if(!/getContext|Not implemented/.test(e.message))errs.push('jsdom:'+e.message)});vc.on('error',e=>errs.push('console:'+e));
const sleep=ms=>new Promise(r=>setTimeout(r,ms));let fails=0;const ok=(n,c,x='')=>{console.log(n.padEnd(22),c?'OK':'FAIL',x);if(!c)fails++};
(async()=>{
 await fetch(base+'/api/admin/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:'RESET'})});
 const html=fs.readFileSync(path.join(fe,'index.html'),'utf8').replace(/<link[^>]*googleapis[^>]*>/g,'').replace('<script src="app.js"></script>','');
 const dom=new JSDOM(html,{url:base+'/',runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:vc});const w=dom.window;
 w.fetch=(u,o)=>fetch(u.startsWith('http')?u:base+u,o);w.HTMLCanvasElement.prototype.getContext=()=>({clearRect(){},beginPath(){},moveTo(){},lineTo(){},stroke(){},arc(){},fill(){}});
 w.matchMedia=()=>({matches:true});w.eval(fs.readFileSync(path.join(fe,'app.js'),'utf8'));await sleep(1200);
 const $=s=>w.document.querySelector(s);
 ok('welcome dialog',!$('#modal').hidden);$('#wc').click();
 ok('9 nav items',w.document.querySelectorAll('#nav a').length===9);
 for(const id of ['home','dashboard','twin','behavior','events','live','submit','threats','risk','xai','devices','network','investigate','response','reports','settings']){
  w.location.hash='#/'+id;await sleep(1000);const t=$('#main').textContent;ok(id,t.trim().length>60&&!/Could not load|undefined|\[object/.test(t),t.length)}
 w.location.hash='#/twin';await sleep(900);ok('twin svg nodes',w.document.querySelectorAll('svg .tn').length>=4);
 $('svg .tn').dispatchEvent(new w.Event('click',{bubbles:true}));
 w.document.querySelectorAll('svg .tn')[1].dispatchEvent(new w.Event('click',{bubbles:true}));await sleep(500);ok('node details',/familiar|unusual/.test($('#nodeinfo').textContent),$('#nodeinfo').textContent.slice(0,60));
 // sample event form
 w.location.hash='#/submit';await sleep(900);const f=$('#sample');f.querySelector('[name=device]').value='Personal Laptop';f.querySelector('[name=network]').value='Home Wi-Fi';
 f.dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await sleep(1200);ok('sample event result',/Priority score/.test($('#sres').textContent));
 // guided demo
 $('[data-act=guide]').click();await sleep(1500);ok('guide step 1',/1\. Welcome/.test($('#guide').textContent));$('#wc')&&$('#wc').click();
 for(let i=0;i<11;i++){const n=$('#gn');if(!n)break;n.click();await sleep(1700);if(!$('#modal').hidden&&$('#fsave')){ $('#fsv')&&0;$('#fv').value='true_positive';$('#fsave').click();await sleep(900)}}
 ok('guide reached report',/12\. Generate/.test($('#guide').textContent)||$('#guide').hidden);
 const t=await (await fetch(base+'/api/twin')).json();ok('demo produced event',t.summary.latest_unusual!==null&&t.summary.feedback.total>=1);
 // offline behaviour
 const real=w.fetch;w.fetch=()=>Promise.reject(new TypeError('x'));w.location.hash='#/devices';await sleep(900);ok('offline message',/Cannot reach|Waiting/.test($('#main').textContent)&&!$('#offline').hidden);w.fetch=real;
 console.log('JS ERRORS',JSON.stringify(errs));process.exit(fails||errs.length?1:0)})();

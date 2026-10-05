// nHash web explorer — a MoneroOcean-style dashboard for your coin on the local network.
// A tiny HTTP server that queries the node's RPC and serves a live page: network stats,
// recent blocks, and an address lookup (balance / mature / pending). Read-only.
//
// Usage: nhash-web <node_host:rpcport> <http_port>
//   e.g. nhash-web 127.0.0.1:9334 8080   then browse http://SERVER_IP:8080 on the LAN.
#include "net.h"
#include "params.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <thread>
#ifndef _WIN32
#include <sys/time.h>
#endif

static std::string g_node_host; static uint16_t g_node_port;
static std::string g_pool_host; static uint16_t g_pool_port = 0;   // optional

// Bound how long an RPC socket may block, so one slow/hung node call can't tie up a
// worker thread forever (defence in depth on top of the thread-per-connection server).
static void set_sock_timeout(sock_t s, int secs) {
#ifdef _WIN32
    DWORD ms = (DWORD)secs * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof(ms));
#else
    struct timeval tv; tv.tv_sec = secs; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}
static bool rpc_to(const std::string& host, uint16_t port, const std::string& req, std::string& resp) {
    sock_t s = net::connect_to(host, port);
    if (s == CH_BADSOCK) return false;
    set_sock_timeout(s, 8);
    std::vector<uint8_t> out(req.begin(), req.end()); uint8_t type; std::vector<uint8_t> pl;
    bool ok = net::send_msg(s, 1, out) && net::recv_msg(s, type, pl);
    net::close_sock(s);
    if (ok) resp.assign((char*)pl.data(), pl.size());
    return ok;
}
static bool node_rpc(const std::string& req, std::string& resp) { return rpc_to(g_node_host, g_node_port, req, resp); }
static bool pool_rpc(const std::string& req, std::string& resp) { return g_pool_port && rpc_to(g_pool_host, g_pool_port, req, resp); }

// Parse getutxos "OK <tip> <n> txid:index:amount:height:cb ..." into an address JSON.
static std::string address_json(const std::string& addr) {
    std::string resp;
    if (addr.size() != 64) return "{\"error\":\"address must be 64 hex chars\"}";
    if (!node_rpc("getutxos " + addr, resp) || resp.rfind("OK ", 0) != 0)
        return "{\"error\":\"node unreachable\"}";
    std::istringstream is(resp.substr(3)); uint64_t tip = 0, n = 0; is >> tip >> n;
    uint64_t next_h = tip + 1, mature = 0, immature = 0, count = 0;
    for (uint64_t i = 0; i < n; i++) {
        std::string item; if (!(is >> item)) break;
        std::vector<std::string> f; size_t p = 0;
        for (int k = 0; k < 4; k++) { auto q = item.find(':', p); f.push_back(item.substr(p, q - p)); p = q + 1; }
        f.push_back(item.substr(p));
        if (f.size() < 5) continue;
        uint64_t amount = strtoull(f[2].c_str(), nullptr, 10);
        uint64_t h = strtoull(f[3].c_str(), nullptr, 10); bool cb = f[4] == "1";
        if (cb && next_h < h + g_params.coinbase_maturity) immature += amount; else mature += amount;
        count++;
    }
    char buf[320];
    snprintf(buf, sizeof(buf),
      "{\"address\":\"%s\",\"balance\":%llu,\"mature\":%llu,\"immature\":%llu,\"utxos\":%llu,\"tip\":%llu",
      addr.c_str(), (unsigned long long)(mature + immature), (unsigned long long)mature,
      (unsigned long long)immature, (unsigned long long)count, (unsigned long long)tip);
    std::string js = buf;
    // Merge this address's pool status (shares this round / pending / paid), if a pool is set.
    std::string presp;
    if (pool_rpc("stats " + addr, presp) && presp.rfind("OK ", 0) == 0) {
        std::istringstream ps(presp.substr(3));
        unsigned long long sh = 0, ow = 0, pd = 0; ps >> sh >> ow >> pd;
        char pb[160];
        snprintf(pb, sizeof(pb), ",\"pool_shares\":%llu,\"pool_owed\":%llu,\"pool_paid\":%llu", sh, ow, pd);
        js += pb;
    }
    js += "}";
    return js;
}

static std::map<std::string, std::string> parse_query(const std::string& q) {
    std::map<std::string, std::string> m; size_t p = 0;
    while (p < q.size()) { size_t amp = q.find('&', p);
        std::string kv = q.substr(p, amp == std::string::npos ? std::string::npos : amp - p);
        auto eq = kv.find('='); if (eq != std::string::npos) m[kv.substr(0, eq)] = kv.substr(eq + 1);
        if (amp == std::string::npos) break; p = amp + 1; }
    return m;
}
static void http_send(sock_t c, const std::string& body, const char* ctype = "application/json", const char* status = "200 OK") {
    std::string h = "HTTP/1.1 " + std::string(status) + "\r\nContent-Type: " + ctype +
        "\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\nConnection: close\r\n\r\n" + body;
    ::send(c, h.data(), (int)h.size(), 0);
}

static const char* PAGE = R"HTML(<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nHash Explorer</title><style>
:root{--bg:#0e1216;--card:#171d24;--card2:#1e252e;--ink:#e8edf2;--mut:#8a95a3;--acc:#7b68ee;--acc2:#9d8cf0;--ok:#4faf7c;--bd:#28303a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,Segoe UI,Roboto,sans-serif;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:26px 18px 70px}
h1{margin:0;font-size:24px;letter-spacing:-.02em}.logo{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--acc),#5a48c8);color:#fff;font-weight:800;font-family:ui-monospace,monospace;margin-right:10px;vertical-align:middle}
.sub{color:var(--mut);font-size:13px;margin:4px 0 22px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}@media(min-width:640px){.grid{grid-template-columns:repeat(3,1fr)}}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px}
.k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
.v{font-size:20px;font-weight:700;margin-top:3px;font-variant-numeric:tabular-nums}
h2{font-size:14px;color:var(--acc2);text-transform:uppercase;letter-spacing:.06em;margin:28px 0 10px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);white-space:nowrap}
th{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}td.mono,.mono{font-family:ui-monospace,monospace;font-size:12.5px}
.scroll{overflow-x:auto;border:1px solid var(--bd);border-radius:12px}
.look{display:flex;gap:8px;margin-top:6px}input{flex:1;background:var(--card2);border:1px solid var(--bd);color:var(--ink);border-radius:9px;padding:11px 13px;font-family:ui-monospace,monospace;font-size:13px}
button{background:var(--acc);color:#fff;border:0;border-radius:9px;padding:11px 18px;font-weight:700;cursor:pointer}
.res{margin-top:12px;display:none}.res.show{display:block}.big{font-size:22px;font-weight:800;color:var(--ok)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px}.off{background:#c0563e}
a{color:var(--acc2)}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin-top:12px}
.barlab{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);margin:2px 0 7px}
.barlab b{color:var(--ink)}
.bar{height:12px;border-radius:7px;background:var(--card2);overflow:hidden;border:1px solid var(--bd)}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc),var(--ok));transition:width .6s ease}
.charts{display:grid;grid-template-columns:1fr;gap:12px}@media(min-width:640px){.charts{grid-template-columns:1fr 1fr}}
.chart{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px 14px}
.chart .t{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin-bottom:2px}
.chart .t b{color:var(--ink);font-size:15px;float:right;font-variant-numeric:tabular-nums}
.chart svg{width:100%;height:96px;display:block;margin-top:6px}
tbody tr.clk{cursor:pointer}tbody tr.clk:hover{background:var(--card2)}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:flex-start;justify-content:center;overflow:auto;z-index:10;padding:24px 12px}
.ov.show{display:flex}
.modal{background:var(--card);border:1px solid var(--bd);border-radius:14px;max-width:900px;width:100%;padding:18px 20px}
.modal h3{margin:0 0 12px;font-size:18px}.modal .x{float:right;cursor:pointer;color:var(--mut);font-size:20px;line-height:1}
.kv{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;font-size:13px;margin-bottom:14px}
.kv .kk{color:var(--mut)}.kv .vv{font-family:ui-monospace,monospace;word-break:break-all}
.tx{border:1px solid var(--bd);border-radius:10px;padding:10px 12px;margin-top:8px}
.tx .th{font-size:12px;color:var(--acc2);margin-bottom:4px}.tx .io{font-size:12.5px;font-family:ui-monospace,monospace;word-break:break-all}
.tx .out{color:var(--ok)}.badge{font-size:10px;background:var(--acc);color:#fff;border-radius:6px;padding:1px 6px;margin-left:6px}
</style></head><body><div class="wrap">
<h1><span class="logo">n</span>nHash Explorer</h1>
<div class="sub"><span id="live" class="dot off"></span><span id="status">connecting…</span></div>

<div class="grid">
  <div class="card"><div class="k">Height</div><div class="v" id="height">—</div></div>
  <div class="card"><div class="k">Difficulty</div><div class="v" id="diff">—</div></div>
  <div class="card"><div class="k">Network hashrate</div><div class="v" id="hr">—</div></div>
  <div class="card"><div class="k">Peers</div><div class="v" id="peers">—</div></div>
  <div class="card"><div class="k">Mempool</div><div class="v" id="mempool">—</div></div>
  <div class="card"><div class="k">Supply</div><div class="v" id="supply">—</div></div>
  <div class="card"><div class="k">Block reward</div><div class="v" id="reward">—</div></div>
</div>

<div class="panel">
  <div class="barlab"><span>Circulating supply <b id="supPct">—</b> of 21,000,000 nHash</span><span id="halveTxt">—</span></div>
  <div class="bar"><i id="supBar"></i></div>
</div>

<div class="charts" style="margin-top:12px">
  <div class="chart"><div class="t">Block time (s) · target 300<b id="btNow">—</b></div><svg id="btChart" viewBox="0 0 300 96" preserveAspectRatio="none"></svg></div>
  <div class="chart"><div class="t">Difficulty<b id="dfNow">—</b></div><svg id="dfChart" viewBox="0 0 300 96" preserveAspectRatio="none"></svg></div>
</div>

<div id="poolsec" style="display:none">
<h2>Pool</h2>
<div class="grid">
  <div class="card"><div class="k">Miners</div><div class="v" id="pminers">—</div></div>
  <div class="card"><div class="k">Round shares</div><div class="v" id="pshares">—</div></div>
  <div class="card"><div class="k">Blocks found</div><div class="v" id="pblocks">—</div></div>
  <div class="card"><div class="k">Total paid</div><div class="v" id="ppaid">—</div></div>
</div>
<div class="scroll" style="margin-top:12px"><table><thead><tr><th>Miner</th><th>Shares</th><th>Share %</th><th>Pending</th><th>Paid</th></tr></thead>
<tbody id="pminerstbl"><tr><td colspan="5" style="color:var(--mut)">no miners yet</td></tr></tbody></table></div>
</div>

<div id="mpsec" style="display:none">
<h2>Mempool <span id="mpcount" class="sub" style="font-weight:400"></span></h2>
<div class="scroll"><table><thead><tr><th>Txid</th><th>Size</th><th>Fee</th><th>In</th><th>Out</th><th>Total out</th></tr></thead>
<tbody id="mptbl"></tbody></table></div>
</div>

<h2>Your address</h2>
<div class="look">
  <input id="addr" placeholder="paste your nHash address (64 hex chars)">
  <button onclick="lookup()">Check</button>
</div>
<div class="card res" id="ares" style="margin-top:12px">
  <div class="k">Balance (on-chain)</div><div class="big" id="abal">—</div>
  <div class="k" style="margin-top:8px">available <span id="amat" class="mono"></span> · pending <span id="aimm" class="mono"></span> · <span id="autx"></span> outputs</div>
  <div class="k" id="apoolrow" style="margin-top:6px;display:none">at pool (not yet paid): <span id="apool" class="mono"></span> · shares this round: <span id="apsh"></span></div>
  <div id="ahistwrap" style="margin-top:14px;display:none">
    <div class="k" style="margin-bottom:6px">Transaction history (<span id="ahcount">0</span>)</div>
    <div class="scroll"><table><thead><tr><th>Height</th><th>Age</th><th>Type</th><th>Received</th><th>Sent</th><th>Txid</th></tr></thead>
    <tbody id="ahist"></tbody></table></div>
  </div>
</div>

<h2>Recent blocks</h2>
<div class="look" style="margin-bottom:10px">
  <input id="blk" placeholder="search: block height (42), block hash, or txid (64 hex)">
  <button onclick="searchBlock()">Search</button>
</div>
<div class="scroll"><table><thead><tr><th>Height</th><th>Age</th><th>Txs</th><th>Reward</th><th>Diff</th><th>Miner</th><th>Hash</th></tr></thead>
<tbody id="blocks"><tr><td colspan="7" style="color:var(--mut)">loading…</td></tr></tbody></table></div>

<div class="ov" id="ov" onclick="if(event.target===this)closeBlk()">
  <div class="modal">
    <span class="x" onclick="closeBlk()">&times;</span>
    <h3 id="mTitle">Block</h3>
    <div class="kv" id="mMeta"></div>
    <div id="mTxs"></div>
  </div>
</div>
</div><script>
const COIN=100000000, HALVING=210000, MAXSUPPLY=21000000;
function coins(u){return (u/COIN).toLocaleString(undefined,{maximumFractionDigits:8})+" nHash";}
function hs(x){x=+x;if(x>=1e6)return (x/1e6).toFixed(2)+" MH/s";if(x>=1e3)return (x/1e3).toFixed(2)+" kH/s";return x.toFixed(1)+" H/s";}
function ago(t){let s=Math.max(0,Math.floor(Date.now()/1000-t));if(s<60)return s+"s";if(s<3600)return Math.floor(s/60)+"m";if(s<86400)return Math.floor(s/3600)+"h";return Math.floor(s/86400)+"d";}
function sh(h){return h?h.slice(0,10)+"…":"";}
function fmtUp(s){s=+s;const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+"d "+h+"h":(h?h+"h "+m+"m":m+"m");}
// Minimal dependency-free SVG line+area chart (dark theme colors baked in).
function chart(id,vals,opts){opts=opts||{};const el=document.getElementById(id);if(!el)return;
  const W=300,H=96,pad=6;if(!vals.length){el.innerHTML='';return;}
  let mn=Math.min(...vals),mx=Math.max(...vals);
  if(opts.min!=null)mn=Math.min(mn,opts.min);if(opts.max!=null)mx=Math.max(mx,opts.max);
  if(mx-mn<1e-9)mx=mn+1;
  const X=k=>pad+k*(W-2*pad)/((vals.length-1)||1), Y=v=>H-pad-(v-mn)*(H-2*pad)/(mx-mn);
  const d=vals.map((v,k)=>(k?'L':'M')+X(k).toFixed(1)+' '+Y(v).toFixed(1)).join(' ');
  const area=d+' L'+X(vals.length-1).toFixed(1)+' '+(H-pad)+' L'+pad+' '+(H-pad)+' Z';
  let tgt='';if(opts.target!=null&&opts.target>=mn&&opts.target<=mx){const ty=Y(opts.target).toFixed(1);
    tgt=`<line x1="${pad}" y1="${ty}" x2="${W-pad}" y2="${ty}" stroke="#c0563e" stroke-width="1" stroke-dasharray="4 3" opacity=".7"/>`;}
  el.innerHTML=`<defs><linearGradient id="g_${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7b68ee" stop-opacity=".35"/><stop offset="1" stop-color="#7b68ee" stop-opacity="0"/></linearGradient></defs>`+
    `<path d="${area}" fill="url(#g_${id})"/>`+tgt+`<path d="${d}" fill="none" stroke="#9d8cf0" stroke-width="1.6" vector-effect="non-scaling-stroke"/>`;}
async function tick(){
  try{
    const i=await (await fetch('/api/info')).json();
    height.textContent=(+i.height).toLocaleString(); diff.textContent=(+i.difficulty).toFixed(2);
    hr.textContent=hs(i.net_hashrate); peers.textContent=i.peers;
    supply.textContent=coins(i.supply); reward.textContent=coins(i.reward);
    document.getElementById('mempool').textContent=(i.mempool!=null?i.mempool+' tx':'—');
    const up=(i.uptime!=null?fmtUp(i.uptime):'');
    document.getElementById('live').className='dot';
    document.getElementById('status').textContent='live · '+(i.net||'')+' · v'+(i.version!=null?i.version:'?')+(up?' · up '+up:'')+' · tip '+sh(i.tip);
    // supply + halving progress
    const circ=i.supply/COIN, pct=Math.min(100,circ/MAXSUPPLY*100);
    document.getElementById('supBar').style.width=pct.toFixed(3)+'%';
    document.getElementById('supPct').textContent=pct.toFixed(4)+'%';
    const toHalve=HALVING-((+i.height)%HALVING), days=toHalve*(+i.block_time)/86400;
    document.getElementById('halveTxt').textContent='next halving in '+toHalve.toLocaleString()+' blocks (~'+days.toFixed(0)+'d)';
    const b=await (await fetch('/api/blocks')).json();
    // charts (oldest→newest)
    const bl=(b.blocks||[]).slice().reverse();
    const times=bl.map(x=>+x.time), diffs=bl.map(x=>+x.diff||0), iv=[];
    for(let k=1;k<times.length;k++){let dt=times[k]-times[k-1]; if(dt<0)dt=0; iv.push(dt);}
    // clamp charted intervals to 3x target so one restart-gap outlier doesn't flatten the rest
    const cap=3*(+i.block_time), ivc=iv.map(v=>Math.min(v,cap));
    chart('btChart',ivc,{target:+i.block_time,min:0});
    chart('dfChart',diffs,{min:0});
    document.getElementById('btNow').textContent=iv.length?iv[iv.length-1]+'s':'—';
    document.getElementById('dfNow').textContent=diffs.length?diffs[diffs.length-1].toFixed(2):'—';
    document.getElementById('blocks').innerHTML=b.blocks.map(x=>
      `<tr class=clk onclick="openBlk(${x.height})"><td>${(+x.height).toLocaleString()}</td><td>${ago(x.time)}</td><td>${x.txs}</td><td class=mono>${coins(x.reward)}</td><td class=mono>${(+x.diff||0).toFixed(2)}</td><td class=mono>${sh(x.miner)}</td><td class=mono>${sh(x.hash)}</td></tr>`).join('');
  }catch(e){document.getElementById('live').className='dot off';document.getElementById('status').textContent='node offline';}
  try{
    const p=await (await fetch('/api/pool')).json();
    const sec=document.getElementById('poolsec');
    if(p.enabled===false){sec.style.display='none';return;}
    sec.style.display='block';
    document.getElementById('pminers').textContent=p.miners_count;
    document.getElementById('pshares').textContent=p.round_shares;
    document.getElementById('pblocks').textContent=p.blocks_found;
    document.getElementById('ppaid').textContent=coins(p.total_paid);
    const tot=p.round_shares||1;
    const rows=(p.miners||[]).slice().sort((a,b)=>b.shares-a.shares).map(m=>
      `<tr><td class=mono>${sh(m.addr)}</td><td>${m.shares}</td><td>${((m.shares/tot)*100).toFixed(1)}%</td><td class=mono>${coins(m.owed)}</td><td class=mono>${coins(m.paid)}</td></tr>`).join('');
    document.getElementById('pminerstbl').innerHTML=rows||'<tr><td colspan=5 style="color:var(--mut)">no miners yet</td></tr>';
  }catch(e){}
  try{
    const m=await (await fetch('/api/mempool')).json();
    const sec=document.getElementById('mpsec');
    if(!m.txs||!m.count){sec.style.display='none';}
    else{sec.style.display='block';
      document.getElementById('mpcount').textContent='· '+m.count+' pending';
      document.getElementById('mptbl').innerHTML=m.txs.map(x=>
        `<tr><td class=mono><a href="#" onclick="openTx('${x.txid}');return false">${sh(x.txid)}</a></td>`+
        `<td>${x.size} B</td><td class=mono>${coins(x.fee)}</td><td>${x.vin}</td><td>${x.vout}</td><td class=mono>${coins(x.total_out)}</td></tr>`).join('');
    }
  }catch(e){}
}
async function lookup(){
  const a=document.getElementById('addr').value.trim();
  const r=document.getElementById('ares'); r.className='card res show';
  try{const d=await (await fetch('/api/address?a='+encodeURIComponent(a))).json();
    if(d.error){abal.textContent=d.error;amat.textContent='';aimm.textContent='';autx.textContent='0';document.getElementById('ahistwrap').style.display='none';return;}
    abal.textContent=coins(d.balance); amat.textContent=coins(d.mature); aimm.textContent=coins(d.immature); autx.textContent=d.utxos;
    const pr=document.getElementById('apoolrow');
    if(d.pool_owed!==undefined){pr.style.display='block';document.getElementById('apool').textContent=coins(d.pool_owed);document.getElementById('apsh').textContent=d.pool_shares;}
    else pr.style.display='none';
    // transaction history
    const hw=document.getElementById('ahistwrap');
    try{const h=await (await fetch('/api/addrtxs?a='+encodeURIComponent(a))).json();
      if(h.error||!h.txs){hw.style.display='none';}
      else{document.getElementById('ahcount').textContent=h.txcount;
        document.getElementById('ahist').innerHTML = h.txs.length ? h.txs.map(x=>{
          const net=x.received-x.sent;
          const type=x.coinbase?'<span class=badge>mined</span>':(net>=0?'received':'sent');
          return `<tr><td><a href="#" onclick="openBlk(${x.height});return false">#${x.height}</a></td>`+
            `<td>${ago(x.time)}</td><td>${type}</td>`+
            `<td class=mono>${x.received?coins(x.received):'—'}</td>`+
            `<td class=mono>${x.sent?coins(x.sent):'—'}</td>`+
            `<td class=mono><a href="#" onclick="openTx('${x.txid}');return false">${sh(x.txid)}</a></td></tr>`;
        }).join('') : '<tr><td colspan=6 style="color:var(--mut)">no transactions yet</td></tr>';
        hw.style.display='block';}
    }catch(e){hw.style.display='none';}
  }catch(e){abal.textContent='lookup failed';}
}
// ---- block / tx detail ----
function txCard(tx){
  const ins=tx.coinbase?'<span class=io>coinbase (newly minted)</span>':
    tx.vin.map(v=>`<div class=io>${sh(v.txid)}:${v.index}</div>`).join('');
  const outs=tx.vout.map(o=>`<div class="io out">+${coins(o.amount)} → <a href="#" onclick="lookupAddr('${o.addr}');return false">${o.addr}</a></div>`).join('');
  return `<div class=tx><div class=th><a href="#" onclick="openTx('${tx.txid}');return false">tx ${sh(tx.txid)}</a>${tx.coinbase?'<span class=badge>coinbase</span>':''}</div>`+
         `<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">`+
         `<div><div class=kk style="font-size:11px">inputs</div>${ins}</div>`+
         `<div><div class=kk style="font-size:11px">outputs</div>${outs}</div></div></div>`;
}
function show(){document.getElementById('ov').classList.add('show');}
function renderBlk(d){
  document.getElementById('mTitle').textContent='Block #'+(+d.height).toLocaleString();
  const t=new Date(d.time*1000).toLocaleString();
  document.getElementById('mMeta').innerHTML=
    `<div class=kk>Hash</div><div class=vv>${d.hash}</div>`+
    `<div class=kk>Prev</div><div class=vv><a href="#" onclick="openBlk('${d.prev}');return false">${d.prev}</a></div>`+
    `<div class=kk>Merkle</div><div class=vv>${d.merkle}</div>`+
    `<div class=kk>Time</div><div class=vv>${t}</div>`+
    `<div class=kk>Difficulty</div><div class=vv>${(+d.diff).toFixed(3)}</div>`+
    `<div class=kk>Nonce</div><div class=vv>${d.nonce}</div>`+
    `<div class=kk>Size</div><div class=vv>${d.size} bytes</div>`+
    `<div class=kk>Txs</div><div class=vv>${d.txs.length}</div>`;
  document.getElementById('mTxs').innerHTML=d.txs.map(txCard).join('');
}
function renderTx(t){
  document.getElementById('mTitle').textContent='Transaction';
  const ts=new Date(t.time*1000).toLocaleString();
  document.getElementById('mMeta').innerHTML=
    `<div class=kk>Txid</div><div class=vv>${t.txid}</div>`+
    `<div class=kk>Block</div><div class=vv><a href="#" onclick="openBlk(${t.block});return false">#${t.block}</a> (${t.confirmations} conf)</div>`+
    `<div class=kk>Time</div><div class=vv>${ts}</div>`+
    `<div class=kk>Total out</div><div class=vv>${coins(t.total_out)}</div>`;
  document.getElementById('mTxs').innerHTML=txCard(t);
}
async function openBlk(id){try{const d=await (await fetch('/api/block?id='+encodeURIComponent(id))).json();if(d.error){alert('Block not found');return;}renderBlk(d);show();}catch(e){alert('lookup failed');}}
async function openTx(id){try{const d=await (await fetch('/api/tx?id='+encodeURIComponent(id))).json();if(d.error){alert('Transaction not found');return;}renderTx(d);show();}catch(e){alert('lookup failed');}}
function lookupAddr(a){closeBlk();const el=document.getElementById('addr');el.value=a;lookup();el.scrollIntoView({behavior:'smooth',block:'center'});}
// Smart search: number -> block height; 64-hex -> block, else tx, else address.
async function searchBlock(){
  const v=document.getElementById('blk').value.trim(); if(!v)return;
  if(/^[0-9]+$/.test(v)){openBlk(v);return;}
  if(/^[0-9a-fA-F]{64}$/.test(v)){
    let d=await (await fetch('/api/block?id='+v)).json(); if(!d.error){renderBlk(d);show();return;}
    let t=await (await fetch('/api/tx?id='+v)).json();    if(!t.error){renderTx(t);show();return;}
    lookupAddr(v); return;
  }
  alert('Enter a block height, or a 64-hex block hash / txid.');
}
function closeBlk(){document.getElementById('ov').classList.remove('show');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeBlk();});
document.getElementById('blk').addEventListener('keydown',e=>{if(e.key==='Enter')searchBlock();});
document.getElementById('addr').addEventListener('keydown',e=>{if(e.key==='Enter')lookup();});
tick(); setInterval(tick,5000);
</script></body></html>)HTML";

static void handle(sock_t c) {
    char buf[8192]; int n = ::recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { net::close_sock(c); return; }
    buf[n] = 0;
    std::string req(buf); size_t s1 = req.find(' '), s2 = req.find(' ', s1 + 1);
    std::string target = (s1 != std::string::npos && s2 != std::string::npos) ? req.substr(s1 + 1, s2 - s1 - 1) : "/";
    std::string path = target, query;
    auto qm = target.find('?'); if (qm != std::string::npos) { path = target.substr(0, qm); query = target.substr(qm + 1); }

    if (path == "/" || path == "/index.html") { http_send(c, PAGE, "text/html; charset=utf-8"); net::close_sock(c); return; }
    std::string resp, body;
    if (path == "/api/info") { body = node_rpc("chaininfo", resp) ? resp : "{\"error\":\"node offline\"}"; }
    else if (path == "/api/blocks") { body = node_rpc("recentblocks 24", resp) ? resp : "{\"blocks\":[]}"; }
    else if (path == "/api/block") { auto q = parse_query(query); std::string id = q.count("id") ? q["id"] : "";
        body = (!id.empty() && node_rpc("getblock " + id, resp)) ? resp : "{\"error\":\"not found\"}"; }
    else if (path == "/api/tx") { auto q = parse_query(query); std::string id = q.count("id") ? q["id"] : "";
        body = (!id.empty() && node_rpc("gettx " + id, resp)) ? resp : "{\"error\":\"not found\"}"; }
    else if (path == "/api/pool") { body = (g_pool_port && pool_rpc("poolstats", resp)) ? resp : "{\"enabled\":false}"; }
    else if (path == "/api/mempool") { body = node_rpc("getmempool", resp) ? resp : "{\"count\":0,\"txs\":[]}"; }
    else if (path == "/api/address") { auto q = parse_query(query); body = address_json(q.count("a") ? q["a"] : ""); }
    else if (path == "/api/addrtxs") { auto q = parse_query(query); std::string a = q.count("a") ? q["a"] : "";
        body = (a.size() == 64 && node_rpc("getaddrtxs " + a, resp)) ? resp : "{\"error\":\"node unreachable\"}"; }
    else { http_send(c, "{\"error\":\"not found\"}", "application/json", "404 Not Found"); net::close_sock(c); return; }
    http_send(c, body);
    net::close_sock(c);
}

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: nhash-web <node_host:rpcport> <http_port> [pool_host:port]\n"); return 1; }
    select_mainnet();
    std::string hp = argv[1]; auto pos = hp.rfind(':');
    g_node_host = hp.substr(0, pos); g_node_port = (uint16_t)atoi(hp.substr(pos + 1).c_str());
    uint16_t http_port = (uint16_t)atoi(argv[2]);
    if (argc >= 4) { std::string p = argv[3]; auto pp = p.rfind(':');
        g_pool_host = p.substr(0, pp); g_pool_port = (uint16_t)atoi(p.substr(pp + 1).c_str()); }
    setvbuf(stdout, nullptr, _IONBF, 0);
    net::init();
    sock_t ls = net::listen_on(http_port);   // 0.0.0.0 -> reachable on the LAN
    if (ls == CH_BADSOCK) { printf("cannot listen on port %u\n", http_port); return 1; }
    printf("nHash Explorer: http://<this-machine>:%u  (node RPC %s:%u%s)\n", http_port,
           g_node_host.c_str(), g_node_port, g_pool_port ? ", pool linked" : "");
    // Thread-per-connection: a slow request (or a hung node RPC) occupies one worker,
    // never the accept loop, so the explorer can't wedge under concurrent/queued requests.
    while (true) { std::string ip; sock_t c = net::accept_one(ls, ip); if (c == CH_BADSOCK) break; std::thread(handle, c).detach(); }
    return 0;
}

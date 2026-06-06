"""
app.py - Dashboard web del IDS (tema profesional, autocontenido)
================================================================
Panel tipo "SOC" con barra lateral, KPIs, graficas (SVG, sin librerias
externas), vistas separadas (Dashboard / Alertas / Sitios / Listas / IPS /
Configuracion), busqueda y filtros por severidad.

Funciones:
  * Lee la bitacora (logs/ids.db) y la muestra en vivo (auto-refresh).
  * Gestiona listas (blanca/negra) en caliente.
  * Configura el correo (SMTP) en caliente.
  * Controla el Modo IPS (bloqueo automatico) con boton ON/OFF.

Autocontenido: HTML/CSS/JS embebido, sin CDNs (funciona sin internet).

Uso:  ./venv/bin/python3 -m src.web.app   ->  http://127.0.0.1:5000
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3

from flask import Flask, Response, jsonify, request

from src.config_loader import (
    load_settings, load_whitelist, save_whitelist,
    load_blacklist_manual, save_blacklist_manual,
    load_email_config, update_env,
)
from src.paths import BASE_DIR
from src import firewall

app = Flask(__name__)
_settings = load_settings()
_DB = str(BASE_DIR / (_settings.get("logging", {}) or {}).get("database", "logs/ids.db"))


def _query(sql, params=()):
    try:
        conn = sqlite3.connect(_DB)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()
    except Exception:
        return []


def _scalar(sql, params=()):
    try:
        conn = sqlite3.connect(_DB)
        try:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()
    except Exception:
        return 0


def _ip_valida(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _mac_valida(mac: str) -> bool:
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", mac or ""))


# ============================ API de datos ============================
@app.route("/api/data")
def api_data():
    return jsonify({
        "kpis": {
            "visitas": _scalar("SELECT COUNT(*) FROM visitas"),
            "alertas": _scalar("SELECT COUNT(*) FROM alertas"),
            "intrusos": _scalar("SELECT COUNT(*) FROM alertas WHERE severidad='intruso'"),
            "emergencias": _scalar("SELECT COUNT(*) FROM alertas WHERE severidad='emergencia'"),
        },
        "severidades": _query("SELECT severidad, COUNT(*) c FROM alertas "
                              "GROUP BY severidad ORDER BY c DESC"),
        "serie": _query("SELECT substr(fecha,1,16) t, COUNT(*) c FROM visitas "
                        "GROUP BY t ORDER BY t DESC LIMIT 15"),
        "top": _query("SELECT dominio, COUNT(*) c FROM visitas "
                      "GROUP BY dominio ORDER BY c DESC LIMIT 8"),
        "alertas": _query("SELECT fecha, severidad, titulo, src_ip FROM alertas "
                          "ORDER BY id DESC LIMIT 200"),
        "visitas": _query("SELECT fecha, src_ip, dominio, tipo FROM visitas "
                          "ORDER BY id DESC LIMIT 200"),
    })


# ============================ API de listas ============================
@app.route("/api/lists")
def api_lists():
    return jsonify({
        "whitelist": load_whitelist()["equipos"],
        "blacklist": load_blacklist_manual(),
    })


@app.route("/api/whitelist/add", methods=["POST"])
def wl_add():
    d = request.get_json(force=True, silent=True) or {}
    ip = (d.get("ip") or "").strip()
    mac = (d.get("mac") or "").strip()
    name = (d.get("name") or "Equipo").strip()
    if not ip and not mac:
        return jsonify({"ok": False, "error": "Se requiere IP o MAC"}), 400
    if ip and not _ip_valida(ip):
        return jsonify({"ok": False, "error": "IP invalida"}), 400
    if mac and not _mac_valida(mac):
        return jsonify({"ok": False, "error": "MAC invalida (xx:xx:xx:xx:xx:xx)"}), 400
    equipos = load_whitelist()["equipos"]
    equipos.append({"name": name, "ip": ip, "mac": mac})
    save_whitelist(equipos)
    return jsonify({"ok": True})


@app.route("/api/whitelist/delete", methods=["POST"])
def wl_del():
    d = request.get_json(force=True, silent=True) or {}
    ip = (d.get("ip") or "").strip()
    mac = (d.get("mac") or "").strip().lower()
    nuevos = []
    for e in load_whitelist()["equipos"]:
        eip = str(e.get("ip", "")).strip()
        emac = str(e.get("mac", "")).strip().lower()
        if (ip and eip == ip) or (mac and emac == mac):
            continue
        nuevos.append(e)
    save_whitelist(nuevos)
    return jsonify({"ok": True})


@app.route("/api/blacklist/add", methods=["POST"])
def bl_add():
    d = request.get_json(force=True, silent=True) or {}
    ip = (d.get("ip") or "").strip()
    desc = (d.get("desc") or "").strip()
    if not _ip_valida(ip):
        return jsonify({"ok": False, "error": "IP invalida"}), 400
    entradas = load_blacklist_manual()
    if not any(e["ip"] == ip for e in entradas):
        entradas.append({"ip": ip, "desc": desc or "Manual"})
        save_blacklist_manual(entradas)
    return jsonify({"ok": True})


@app.route("/api/blacklist/delete", methods=["POST"])
def bl_del():
    d = request.get_json(force=True, silent=True) or {}
    ip = (d.get("ip") or "").strip()
    entradas = [e for e in load_blacklist_manual() if e["ip"] != ip]
    save_blacklist_manual(entradas)
    return jsonify({"ok": True})


# ============================ API de correo ============================
@app.route("/api/email")
def api_email():
    return jsonify(load_email_config())


@app.route("/api/email/save", methods=["POST"])
def email_save():
    d = request.get_json(force=True, silent=True) or {}
    to = (d.get("to") or "").strip()
    if to and "@" not in to:
        return jsonify({"ok": False, "error": "Correo destino invalido"}), 400
    updates = {}
    for campo, clave in [("host", "SMTP_HOST"), ("port", "SMTP_PORT"),
                         ("user", "SMTP_USER"), ("to", "ALERT_TO"), ("from", "ALERT_FROM")]:
        v = (d.get(campo) or "").strip()
        if v:
            updates[clave] = v
    pwd = (d.get("password") or "").strip()
    if pwd:
        updates["SMTP_PASSWORD"] = pwd
    if not updates:
        return jsonify({"ok": False, "error": "Nada que guardar"}), 400
    update_env(updates)
    return jsonify({"ok": True})


# ============================ API de Modo IPS ============================
@app.route("/api/email/test", methods=["POST"])
def email_test():
    from src.notifier import enviar_prueba
    ok, msg = enviar_prueba(_settings)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/ips")
def api_ips():
    return jsonify({"enabled": firewall.esta_activo(),
                    "blocked": firewall.listar_bloqueadas()})


@app.route("/api/ips/toggle", methods=["POST"])
def ips_toggle():
    firewall.set_activo(not firewall.esta_activo())
    return jsonify({"ok": True, "enabled": firewall.esta_activo()})


@app.route("/api/ips/clear", methods=["POST"])
def ips_clear():
    n = firewall.limpiar()
    return jsonify({"ok": True, "eliminadas": n})


@app.route("/")
def index():
    return Response(PAGINA, mimetype="text/html")


PAGINA = r"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDS - Panel de Seguridad</title>
<style>
 :root{
   --bg:#0a0d16; --panel:#121726; --panel2:#171d30; --border:#222a42;
   --txt:#e6e9f2; --muted:#8b93a9; --accent:#6366f1; --accent2:#818cf8;
   --green:#3fb950; --red:#f85149; --orange:#d29922; --blue:#58a6ff; --purple:#a371f7;
 }
 *{box-sizing:border-box;margin:0;padding:0;}
 body{background:var(--bg);color:var(--txt);
   font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:14px;}
 a{cursor:pointer;text-decoration:none;color:inherit;}
 .app{display:flex;min-height:100vh;}

 /* Sidebar */
 .sidebar{width:230px;background:linear-gradient(180deg,#0e1320,#0a0d16);
   border-right:1px solid var(--border);padding:22px 16px;display:flex;flex-direction:column;
   position:sticky;top:0;height:100vh;}
 .brand{display:flex;align-items:center;gap:10px;font-size:19px;font-weight:700;
   margin-bottom:28px;padding:0 6px;}
 .brand .logo{width:34px;height:34px;border-radius:9px;
   background:linear-gradient(135deg,var(--accent),var(--purple));
   display:flex;align-items:center;justify-content:center;font-size:18px;}
 .nav a{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:10px;
   color:var(--muted);font-weight:500;margin-bottom:4px;transition:.15s;}
 .nav a:hover{background:var(--panel);color:var(--txt);}
 .nav a.active{background:linear-gradient(90deg,rgba(99,102,241,.22),rgba(99,102,241,.05));
   color:#fff;box-shadow:inset 3px 0 0 var(--accent);}
 .nav a .ic{width:20px;text-align:center;font-size:15px;}
 .side-foot{margin-top:auto;display:flex;align-items:center;gap:8px;color:var(--green);
   font-size:12px;padding:10px 12px;}
 .dot{width:9px;height:9px;border-radius:50%;background:var(--green);
   box-shadow:0 0 8px var(--green);animation:pulse 1.4s infinite;}
 @keyframes pulse{0%{opacity:1}50%{opacity:.3}100%{opacity:1}}

 /* Content */
 .content{flex:1;padding:26px 32px;}
 .content>*{max-width:1200px;margin-left:auto;margin-right:auto;}
 .topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;}
 .topbar h1{font-size:22px;font-weight:700;}
 .clock{color:var(--muted);font-size:13px;font-variant-numeric:tabular-nums;}
 .view.hidden{display:none;}

 /* KPI cards */
 .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px;}
 .kpi{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;
   display:flex;align-items:center;gap:14px;}
 .kpi-ic{width:46px;height:46px;border-radius:11px;display:flex;align-items:center;
   justify-content:center;font-size:20px;flex-shrink:0;}
 .kpi-num{font-size:26px;font-weight:700;line-height:1;}
 .kpi-lbl{color:var(--muted);font-size:12px;margin-top:5px;text-transform:uppercase;letter-spacing:.5px;}

 /* Panels */
 .panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;
   padding:18px 20px;margin-bottom:22px;}
 .panel h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;
   margin-bottom:16px;font-weight:600;}
 .grid-2{display:grid;grid-template-columns:1.6fr 1fr;gap:22px;}
 @media(max-width:900px){.grid-2{grid-template-columns:1fr;}.kpis{grid-template-columns:repeat(2,1fr);}
   .sidebar{width:64px;} .brand span,.nav a span.lbl,.side-foot span{display:none;}}

 table{width:100%;border-collapse:collapse;}
 th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--border);font-size:13px;}
 th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;}
 tr:last-child td{border-bottom:none;}
 tbody tr:hover{background:var(--panel2);}

 .bar-row{display:flex;align-items:center;gap:10px;margin:9px 0;}
 .bar-row .name{width:160px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px;}
 .bar{height:9px;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:5px;min-width:4px;}
 .bar-row .val{color:var(--muted);font-size:12px;}

 .tag{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;}
 .tag.emergencia{background:rgba(248,81,73,.16);color:var(--red);}
 .tag.intruso{background:rgba(210,153,34,.16);color:var(--orange);}
 .tag.forense{background:rgba(88,166,255,.16);color:var(--blue);}
 .tag.bloqueo{background:rgba(163,113,247,.16);color:var(--purple);}

 .toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;}
 input,select{background:var(--bg);border:1px solid var(--border);color:var(--txt);
   padding:9px 12px;border-radius:9px;font-family:inherit;font-size:13px;}
 input:focus,select:focus{outline:none;border-color:var(--accent);}
 .toolbar input{flex:1;min-width:160px;}
 .btn{background:var(--accent);color:#fff;border:none;border-radius:9px;padding:9px 16px;
   cursor:pointer;font-family:inherit;font-size:13px;font-weight:600;}
 .btn:hover{background:var(--accent2);}
 .btn.gray{background:#30374e;} .btn.red{background:var(--red);}
 .btn.sm{padding:4px 10px;font-size:12px;}

 .lists{display:grid;grid-template-columns:1fr 1fr;gap:22px;}
 @media(max-width:900px){.lists{grid-template-columns:1fr;}}
 .addform{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;}
 .addform input{flex:1;min-width:80px;}
 .donut-wrap{display:flex;align-items:center;gap:22px;flex-wrap:wrap;}
 .legend div{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;margin:6px 0;}
 .dot2{width:11px;height:11px;border-radius:3px;display:inline-block;}
 .muted{color:var(--muted);}
 .pill{display:inline-block;background:var(--panel2);border:1px solid var(--border);
   border-radius:20px;padding:4px 12px;margin:3px;font-size:12px;}
 .ips-state{font-weight:700;padding:5px 14px;border-radius:20px;}
 .ips-on{background:rgba(248,81,73,.16);color:var(--red);}
 .ips-off{background:var(--panel2);color:var(--muted);}
</style></head><body>
<div class="app">
  <aside class="sidebar">
    <div class="brand"><span class="logo">&#128737;</span> <span>IDS Panel</span></div>
    <nav class="nav">
      <a data-view="dashboard" class="active"><span class="ic">&#9632;</span><span class="lbl">Dashboard</span></a>
      <a data-view="alertas"><span class="ic">&#9888;</span><span class="lbl">Alertas</span></a>
      <a data-view="sitios"><span class="ic">&#127760;</span><span class="lbl">Sitios</span></a>
      <a data-view="listas"><span class="ic">&#9776;</span><span class="lbl">Listas</span></a>
      <a data-view="ips"><span class="ic">&#128737;</span><span class="lbl">Modo IPS</span></a>
      <a data-view="config"><span class="ic">&#9993;</span><span class="lbl">Correo</span></a>
    </nav>
    <div class="side-foot"><span class="dot"></span> <span>EN VIVO</span></div>
  </aside>

  <main class="content">
    <div class="topbar">
      <h1 id="view-title">Dashboard</h1>
      <div class="clock" id="clock"></div>
    </div>

    <!-- DASHBOARD -->
    <section id="v-dashboard" class="view">
      <div class="kpis">
        <div class="kpi"><div class="kpi-ic" style="background:rgba(88,166,255,.15);color:var(--blue);">&#127760;</div>
          <div><div class="kpi-num" id="k-visitas">0</div><div class="kpi-lbl">Visitas</div></div></div>
        <div class="kpi"><div class="kpi-ic" style="background:rgba(63,185,80,.15);color:var(--green);">&#128276;</div>
          <div><div class="kpi-num" id="k-alertas">0</div><div class="kpi-lbl">Alertas</div></div></div>
        <div class="kpi"><div class="kpi-ic" style="background:rgba(210,153,34,.15);color:var(--orange);">&#128100;</div>
          <div><div class="kpi-num" id="k-intrusos">0</div><div class="kpi-lbl">Intrusos</div></div></div>
        <div class="kpi"><div class="kpi-ic" style="background:rgba(248,81,73,.15);color:var(--red);">&#9763;</div>
          <div><div class="kpi-num" id="k-emergencias">0</div><div class="kpi-lbl">IPs Peligrosas</div></div></div>
      </div>
      <div class="grid-2">
        <div class="panel"><h2>Actividad reciente (visitas por minuto)</h2><div id="chart-line"></div></div>
        <div class="panel"><h2>Alertas por tipo</h2><div id="chart-donut" class="donut-wrap"></div></div>
      </div>
      <div class="panel"><h2>Top dominios visitados</h2><div id="top"></div></div>
    </section>

    <!-- ALERTAS -->
    <section id="v-alertas" class="view hidden">
      <div class="panel">
        <div class="toolbar">
          <input id="f-alert-q" placeholder="Buscar por IP o detalle..." oninput="renderAlertas()">
          <select id="f-alert-sev" onchange="renderAlertas()">
            <option value="todas">Todas las severidades</option>
            <option value="emergencia">Emergencia</option>
            <option value="intruso">Intruso</option>
            <option value="forense">Forense</option>
          </select>
        </div>
        <table><thead><tr><th>Fecha</th><th>Tipo</th><th>Origen</th><th>Detalle</th></tr></thead>
        <tbody id="alertas"></tbody></table>
      </div>
    </section>

    <!-- SITIOS -->
    <section id="v-sitios" class="view hidden">
      <div class="panel">
        <div class="toolbar">
          <input id="f-sitio-q" placeholder="Buscar por dominio o IP de origen..." oninput="renderSitios()">
        </div>
        <table><thead><tr><th>Fecha</th><th>Origen</th><th>Dominio</th><th>Tipo</th></tr></thead>
        <tbody id="visitas"></tbody></table>
      </div>
    </section>

    <!-- LISTAS -->
    <section id="v-listas" class="view hidden">
      <div class="panel"><h2>Gestion de listas (cambios en vivo)</h2>
        <div class="lists">
          <div>
            <h2 style="color:var(--green);">&#9989; Lista Blanca (autorizados)</h2>
            <table><thead><tr><th>Nombre</th><th>IP</th><th>MAC</th><th></th></tr></thead>
            <tbody id="wl"></tbody></table>
            <div class="addform">
              <input id="wl-name" placeholder="Nombre"><input id="wl-ip" placeholder="IP">
              <input id="wl-mac" placeholder="MAC (opcional)"><button class="btn" onclick="addWl()">Agregar</button>
            </div>
          </div>
          <div>
            <h2 style="color:var(--red);">&#9888; Lista Negra (IPs peligrosas)</h2>
            <table><thead><tr><th>IP</th><th>Riesgo</th><th></th></tr></thead>
            <tbody id="bl"></tbody></table>
            <div class="addform">
              <input id="bl-ip" placeholder="IP peligrosa"><input id="bl-desc" placeholder="Riesgo">
              <button class="btn" onclick="addBl()">Agregar</button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- IPS -->
    <section id="v-ips" class="view hidden">
      <div class="panel"><h2>Modo IPS &mdash; Prevencion (bloqueo automatico)</h2>
        <p class="muted" style="margin-bottom:16px;">Cuando esta ACTIVO, el IDS bloquea en el firewall a los intrusos y a las IPs peligrosas. Nunca bloquea tu equipo, el gateway ni las IPs autorizadas.</p>
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
          Estado: <span id="ips-state" class="ips-state ips-off">...</span>
          <button id="ips-btn" class="btn" onclick="toggleIps()">Activar IPS</button>
          <button class="btn gray" onclick="limpiarIps()">Limpiar bloqueos</button>
        </div>
        <div style="margin-top:18px;"><h2>IPs bloqueadas</h2><div id="ips-blocked" class="muted">ninguna</div></div>
      </div>
    </section>

    <!-- CONFIG -->
    <section id="v-config" class="view hidden">
      <div class="panel"><h2>Configuracion de correo (SMTP)</h2>
        <p class="muted" style="margin-bottom:16px;">Cambia el servidor, usuario, contrasena y el correo del administrador. Se aplica en la proxima alerta.</p>
        <div class="addform" style="flex-direction:column;align-items:stretch;max-width:560px;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="em-host" placeholder="SMTP host"><input id="em-port" placeholder="Puerto" style="max-width:120px;flex:0 0 120px;">
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="em-user" placeholder="Usuario SMTP"><input id="em-pass" type="password" placeholder="Contrasena">
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="em-to" placeholder="Correo del administrador (destino)"><input id="em-from" placeholder="Remitente (from)">
          </div>
          <div><button class="btn" onclick="saveEmail()">Guardar correo</button>
            <button class="btn gray" onclick="probarEmail()">Enviar correo de prueba</button>
            <span id="em-msg" class="muted" style="margin-left:10px;"></span></div>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
const STATE = {alertas:[], visitas:[]};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function jget(u){const r=await fetch(u);return r.json();}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json();}
const COL={intruso:'#d29922',emergencia:'#f85149',forense:'#58a6ff',bloqueo:'#a371f7'};

// ----- Navegacion entre vistas -----
document.querySelectorAll('.nav a').forEach(a=>{
  a.addEventListener('click',()=>{
    document.querySelectorAll('.nav a').forEach(x=>x.classList.remove('active'));
    a.classList.add('active');
    const v=a.dataset.view;
    document.querySelectorAll('.view').forEach(s=>s.classList.add('hidden'));
    document.getElementById('v-'+v).classList.remove('hidden');
    document.getElementById('view-title').textContent=a.querySelector('.lbl').textContent;
    if(v==='listas')loadLists(); if(v==='config')loadEmail(); if(v==='ips')loadIps();
  });
});

// ----- Reloj -----
setInterval(()=>{document.getElementById('clock').textContent=new Date().toLocaleString();},1000);

// ----- Grafica de linea (SVG) -----
function renderLinea(serie){
  const data=serie.slice().reverse();
  const box=document.getElementById('chart-line');
  if(!data.length){box.innerHTML='<div class="muted">Sin datos aun</div>';return;}
  const w=600,h=170,pad=26,max=Math.max(...data.map(d=>d.c),1);
  const sx=(w-2*pad)/Math.max(data.length-1,1);
  const pts=data.map((d,i)=>[pad+i*sx, h-pad-(d.c/max)*(h-2*pad)]);
  const line=pts.map(p=>p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' L ');
  const area='M '+pts[0][0].toFixed(1)+' '+(h-pad)+' L '+line+' L '+pts[pts.length-1][0].toFixed(1)+' '+(h-pad)+' Z';
  const dots=pts.map(p=>'<circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="3" fill="#818cf8"/>').join('');
  box.innerHTML='<svg viewBox="0 0 '+w+' '+h+'" style="width:100%;height:auto;">'
    +'<defs><linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">'
    +'<stop offset="0" stop-color="rgba(99,102,241,.45)"/><stop offset="1" stop-color="rgba(99,102,241,0)"/></linearGradient></defs>'
    +'<path d="'+area+'" fill="url(#ga)"/>'
    +'<path d="M '+line+'" fill="none" stroke="#818cf8" stroke-width="2.5"/>'+dots
    +'<text x="'+pad+'" y="'+(h-6)+'" fill="#8b93a9" font-size="10">'+esc(data[0].t.slice(11))+'</text>'
    +'<text x="'+(w-pad-30)+'" y="'+(h-6)+'" fill="#8b93a9" font-size="10">'+esc(data[data.length-1].t.slice(11))+'</text></svg>';
}

// ----- Grafica de dona (SVG) -----
function renderDona(sev){
  const box=document.getElementById('chart-donut');
  const total=sev.reduce((s,x)=>s+x.c,0);
  if(!total){box.innerHTML='<div class="muted">Sin alertas aun</div>';return;}
  const r=52,cx=70,cy=70,circ=2*Math.PI*r; let off=0,segs='';
  sev.forEach(x=>{const len=(x.c/total)*circ;
    segs+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+(COL[x.severidad]||'#8b93a9')
      +'" stroke-width="16" stroke-dasharray="'+len.toFixed(2)+' '+(circ-len).toFixed(2)
      +'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')"/>'; off+=len;});
  const leg=sev.map(x=>'<div><span class="dot2" style="background:'+(COL[x.severidad]||'#8b93a9')+'"></span>'
      +esc(x.severidad)+' &middot; '+x.c+'</div>').join('');
  box.innerHTML='<svg viewBox="0 0 140 140" width="150" height="150">'+segs
    +'<text x="70" y="66" text-anchor="middle" fill="#e6e9f2" font-size="26" font-weight="700">'+total+'</text>'
    +'<text x="70" y="86" text-anchor="middle" fill="#8b93a9" font-size="11">alertas</text></svg>'
    +'<div class="legend">'+leg+'</div>';
}

// ----- Render tablas con filtros -----
function renderAlertas(){
  const q=(document.getElementById('f-alert-q').value||'').toLowerCase();
  const sev=document.getElementById('f-alert-sev').value;
  const rows=STATE.alertas.filter(a=>(sev==='todas'||a.severidad===sev)
    && (!q || (a.src_ip||'').toLowerCase().includes(q) || (a.titulo||'').toLowerCase().includes(q)));
  document.getElementById('alertas').innerHTML=rows.map(a=>'<tr><td>'+esc(a.fecha)
    +'</td><td><span class="tag '+esc(a.severidad)+'">'+esc(a.severidad)+'</span></td><td>'
    +esc(a.src_ip)+'</td><td>'+esc(a.titulo)+'</td></tr>').join('')
    ||'<tr><td colspan="4" class="muted">Sin resultados</td></tr>';
}
function renderSitios(){
  const q=(document.getElementById('f-sitio-q').value||'').toLowerCase();
  const rows=STATE.visitas.filter(v=>!q||(v.dominio||'').toLowerCase().includes(q)||(v.src_ip||'').toLowerCase().includes(q));
  document.getElementById('visitas').innerHTML=rows.map(v=>'<tr><td>'+esc(v.fecha)+'</td><td>'
    +esc(v.src_ip)+'</td><td>'+esc(v.dominio)+'</td><td>'+esc(v.tipo)+'</td></tr>').join('')
    ||'<tr><td colspan="4" class="muted">Sin resultados</td></tr>';
}

async function refresh(){
  try{
    const d=await jget('/api/data');
    document.getElementById('k-visitas').textContent=d.kpis.visitas;
    document.getElementById('k-alertas').textContent=d.kpis.alertas;
    document.getElementById('k-intrusos').textContent=d.kpis.intrusos;
    document.getElementById('k-emergencias').textContent=d.kpis.emergencias;
    renderLinea(d.serie); renderDona(d.severidades);
    const max=d.top.length?d.top[0].c:1;
    document.getElementById('top').innerHTML=d.top.map(t=>'<div class="bar-row"><span class="name">'
      +esc(t.dominio)+'</span><span class="bar" style="width:'+Math.max(4,Math.round(t.c/max*100))
      +'%"></span><span class="val">'+t.c+'</span></div>').join('')||'<div class="muted">Sin datos aun</div>';
    STATE.alertas=d.alertas; STATE.visitas=d.visitas;
    renderAlertas(); renderSitios();
  }catch(e){}
}

// ----- Listas -----
async function loadLists(){
  try{
    const d=await jget('/api/lists');
    document.getElementById('wl').innerHTML=d.whitelist.map(e=>'<tr><td>'+esc(e.name)+'</td><td>'+esc(e.ip)
      +'</td><td>'+esc(e.mac)+'</td><td><button class="btn red sm" data-k="wl" data-ip="'+esc(e.ip)
      +'" data-mac="'+esc(e.mac)+'">X</button></td></tr>').join('')||'<tr><td colspan="4" class="muted">(vacia)</td></tr>';
    document.getElementById('bl').innerHTML=d.blacklist.map(e=>'<tr><td>'+esc(e.ip)+'</td><td>'+esc(e.desc)
      +'</td><td><button class="btn red sm" data-k="bl" data-ip="'+esc(e.ip)+'">X</button></td></tr>').join('')
      ||'<tr><td colspan="3" class="muted">(vacia)</td></tr>';
  }catch(e){}
}
function val(id){return document.getElementById(id).value;}
function clr(ids){ids.forEach(i=>document.getElementById(i).value='');}
async function addWl(){const r=await jpost('/api/whitelist/add',{name:val('wl-name'),ip:val('wl-ip'),mac:val('wl-mac')});
  if(!r.ok){alert(r.error||'Error');return;}clr(['wl-name','wl-ip','wl-mac']);loadLists();}
async function addBl(){const r=await jpost('/api/blacklist/add',{ip:val('bl-ip'),desc:val('bl-desc')});
  if(!r.ok){alert(r.error||'Error');return;}clr(['bl-ip','bl-desc']);loadLists();}
document.addEventListener('click',async ev=>{
  const b=ev.target.closest('button[data-k]'); if(!b)return;
  if(b.dataset.k==='wl')await jpost('/api/whitelist/delete',{ip:b.dataset.ip,mac:b.dataset.mac});
  else await jpost('/api/blacklist/delete',{ip:b.dataset.ip});
  loadLists();
});

// ----- Correo -----
async function loadEmail(){try{const d=await jget('/api/email');
  document.getElementById('em-host').value=d.host||'';document.getElementById('em-port').value=d.port||'';
  document.getElementById('em-user').value=d.user||'';document.getElementById('em-to').value=d.to||'';
  document.getElementById('em-from').value=d.from||'';
  document.getElementById('em-pass').placeholder=d.password_set?'(configurada; vacio = sin cambios)':'Contrasena';}catch(e){}}
async function saveEmail(){const r=await jpost('/api/email/save',{host:val('em-host'),port:val('em-port'),
  user:val('em-user'),to:val('em-to'),from:val('em-from'),password:val('em-pass')});
  const m=document.getElementById('em-msg');
  if(!r.ok){m.style.color='var(--red)';m.textContent=r.error||'Error';return;}
  m.style.color='var(--green)';m.textContent='Guardado. Aplica en la proxima alerta.';
  document.getElementById('em-pass').value='';loadEmail();}
async function probarEmail(){const m=document.getElementById('em-msg');
  m.style.color='var(--muted)';m.textContent='Enviando correo de prueba...';
  const r=await jpost('/api/email/test');
  m.style.color=r.ok?'var(--green)':'var(--red)';m.textContent=r.msg||(r.ok?'Enviado':'Error');}

// ----- IPS -----
async function loadIps(){try{const d=await jget('/api/ips');
  const e=document.getElementById('ips-state');
  e.textContent=d.enabled?'ACTIVO':'DESACTIVADO';e.className='ips-state '+(d.enabled?'ips-on':'ips-off');
  document.getElementById('ips-btn').textContent=d.enabled?'Desactivar IPS':'Activar IPS';
  document.getElementById('ips-blocked').innerHTML=(d.blocked&&d.blocked.length)
    ?d.blocked.map(ip=>'<span class="pill">'+esc(ip)+'</span>').join(''):'<span class="muted">ninguna</span>';}catch(e){}}
async function toggleIps(){await jpost('/api/ips/toggle');loadIps();}
async function limpiarIps(){await jpost('/api/ips/clear');loadIps();}

refresh(); loadLists(); loadEmail(); loadIps();
setInterval(()=>{refresh(); if(!document.getElementById('v-ips').classList.contains('hidden'))loadIps();},4000);
</script>
</body></html>"""


def main():
    print("Dashboard del IDS -> http://127.0.0.1:5000   (Ctrl+C para detener)")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()

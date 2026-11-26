"use strict";
/* Atalaia dashboard. No framework, no inline script, and every piece of server data is rendered
   through textContent: evidence comes from scanned sites and must never be interpreted as HTML. */

const API = "/api/v1";
const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", info: "Info" };
const STATUS_LABEL = { open: "Aberto", fixed: "Corrigido", false_positive: "Falso positivo", accepted_risk: "Risco aceito" };
const SCAN_STATUS = { queued: "Na fila", running: "Em andamento", completed: "Concluída", failed: "Falhou", canceled: "Cancelada" };
const STAGE = { crawling: "Mapeando páginas", browser: "Renderizando no navegador", passive: "Análise passiva",
  "host-probes": "Verificações do servidor", "input-probes": "Testando entradas", "stored-xss": "Buscando XSS armazenado",
  "browser-proof": "Comprovando XSS no navegador", starting: "Iniciando", done: "Finalizada" };
const CONFIDENCE = { confirmed: "Confirmada por execução no navegador", high: "Alta", medium: "Média", low: "Baixa" };
const PROFILE = { passive: "Passiva", standard: "Padrão", full: "Completa" };
const ROLE = { owner: "Proprietário", admin: "Administrador", analyst: "Analista", viewer: "Leitor" };
const RANK = { viewer: 0, analyst: 1, admin: 2, owner: 3 };

const state = { token: sessionStorage.getItem("atalaia.token"), me: null, timer: null };
const app = document.getElementById("app");

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function toast(msg, isError) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (isError ? " err" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = ""; }, 4500);
}

async function api(path, opts = {}) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(API + path, { method: opts.method || "GET", headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  if (res.status === 401 && state.token) { logout(); throw new Error("Sessão expirada. Entre novamente."); }
  if (opts.raw) { if (!res.ok) throw new Error("Falha ao gerar o arquivo"); return res; }
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    let detail = data && data.detail;
    if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join("; ");
    const err = new Error(detail || "Erro " + res.status);
    err.data = data;
    throw err;
  }
  return data;
}

const can = (role) => state.me && RANK[state.me.role] >= RANK[role];
const fmt = (iso) => (iso ? new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" }) : "—");
const sevBadge = (s) => h("span", { class: "badge bg-" + s }, SEV_LABEL[s]);
function run(fn) { return async (ev) => { if (ev) ev.preventDefault(); try { await fn(ev); } catch (e) { toast(e.message, true); } }; }

function logout() {
  state.token = null; state.me = null;
  sessionStorage.removeItem("atalaia.token");
  // Changing the hash already triggers a render; rendering twice would wipe what the user typed.
  if (location.hash === "#/login") render(); else location.hash = "#/login";
}

// ---------------------------------------------------------------- overlays
function closeOverlay() { const o = document.querySelector(".overlay"); if (o) o.remove(); }
function overlay(kind, ...content) {
  closeOverlay();
  const box = h("div", { class: kind, role: "dialog", "aria-modal": "true" }, ...content);
  const o = h("div", { class: "overlay" + (kind === "modal" ? " center" : ""),
    onclick: (e) => { if (e.target === o) closeOverlay(); } }, box);
  document.body.append(o);
  const first = box.querySelector("input, select, textarea, button");
  if (first) first.focus();
  return box;
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeOverlay(); });

function field(label, input) { return h("div", {}, h("label", {}, label), input); }

// ---------------------------------------------------------------- auth views
function authView(mode) {
  const isReg = mode === "register";
  const f = { org: h("input", { required: true, minlength: 2 }), name: h("input", { required: true }),
    email: h("input", { type: "email", required: true, autocomplete: "username" }),
    password: h("input", { type: "password", required: true, minlength: isReg ? 12 : 1,
      autocomplete: isReg ? "new-password" : "current-password" }),
    code: h("input", { autocomplete: "one-time-code", inputmode: "numeric", maxlength: 32, placeholder: "000000" }) };
  const codeRow = h("div", { hidden: true }, h("label", {}, "Código de verificação"), f.code,
    h("p", { class: "muted" }, "Abra o aplicativo autenticador. Sem o aparelho, use um código de recuperação."));
  const submit = run(async () => {
    const body = isReg
      ? { organization: f.org.value, name: f.name.value, email: f.email.value, password: f.password.value }
      : { email: f.email.value, password: f.password.value, code: f.code.value };
    let data;
    try {
      data = await api(isReg ? "/auth/register" : "/auth/login", { method: "POST", body });
    } catch (e) {
      if (e.data && e.data.mfa_required) { codeRow.hidden = false; f.code.value = ""; f.code.focus(); }
      throw e;
    }
    state.token = data.token;
    sessionStorage.setItem("atalaia.token", data.token);
    location.hash = "#/";
    await boot();
  });
  return h("div", { class: "auth" }, h("div", { class: "card" },
    h("div", { class: "brand" }, ""),
    h("h1", {}, "Atalaia"),
    h("p", { class: "muted" }, isReg ? "Crie a conta da sua organização." : "Segurança de aplicações web para alvos autorizados."),
    h("form", { onsubmit: submit },
      isReg && field("Organização", f.org), isReg && field("Seu nome", f.name),
      field("E-mail", f.email), field(isReg ? "Senha (mínimo de 12 caracteres)" : "Senha", f.password),
      !isReg && codeRow,
      h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, isReg ? "Criar conta" : "Entrar")),
    ),
    h("p", { class: "muted" }, " "),
    isReg ? h("a", { href: "#/login" }, "Já tenho conta") : h("a", { href: "#/register" }, "Criar uma conta")));
}

// ---------------------------------------------------------------- shell
const NAV = [["#/", "Visão geral"], ["#/targets", "Alvos"], ["#/scans", "Varreduras"], ["#/findings", "Achados"],
  ["#/team", "Equipe e chaves", "admin"], ["#/audit", "Auditoria", "admin"]];

function shell(content) {
  const cur = location.hash.split("?")[0] || "#/";
  return h("div", { class: "layout" },
    h("nav", { class: "side" },
      h("div", { class: "brand" }, "Atalaia", h("small", {}, state.me.organization.name)),
      NAV.filter((n) => !n[2] || can(n[2])).map(([href, label]) =>
        h("a", { class: "nav" + (cur === href ? " active" : ""), href }, label)),
      h("div", { class: "spacer" }),
      h("div", { class: "who" }, state.me.actor, h("br"), ROLE[state.me.role]),
      h("a", { class: "nav" + (cur === "#/account" ? " active" : ""), href: "#/account" }, "Minha conta"),
      h("a", { class: "nav", onclick: logout, href: "#/login" }, "Sair")),
    h("main", { class: "main" }, content));
}

function header(title, subtitle, ...actions) {
  return h("div", { class: "head" }, h("div", {}, h("h1", {}, title), subtitle && h("p", { class: "muted" }, subtitle)),
    h("div", { class: "row" }, ...actions));
}

function table(cols, rows, empty) {
  if (!rows.length) return h("div", { class: "empty" }, empty || "Nada por aqui ainda.");
  return h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))), h("tbody", {}, rows));
}

// ---------------------------------------------------------------- dashboard
async function dashboardView() {
  const d = await api("/dashboard");
  const max = Math.max(1, ...d.open_by_owasp.map((o) => o.count));
  const score = d.security_score;
  return [
    header("Visão geral", "Postura de segurança dos alvos da organização."),
    d.targets === 0 && h("div", { class: "notice" }, "Comece cadastrando um alvo e comprovando que ele é seu. ",
      h("a", { href: "#/targets" }, "Cadastrar alvo")),
    h("div", { class: "grid g5" }, SEV.map((s) => h("div", { class: "stat bg-" + s }, h("b", {}, d.open_by_severity[s]), SEV_LABEL[s]))),
    h("div", { class: "grid g3" },
      h("div", { class: "card" }, h("h2", {}, "Índice de segurança"),
        h("div", { class: "score" }, score === null ? "—" : score), h("p", { class: "muted" }, "De 0 a 100, com base nos achados em aberto.")),
      h("div", { class: "card" }, h("h2", {}, "Alvos"), h("div", { class: "score" }, d.targets),
        h("p", { class: "muted" }, d.verified_targets + " com propriedade verificada")),
      h("div", { class: "card" }, h("h2", {}, "Achados tratados"),
        h("div", { class: "score" }, (d.findings_by_status.fixed || 0)),
        h("p", { class: "muted" }, "corrigidos; " + (d.findings_by_status.accepted_risk || 0) + " riscos aceitos, " +
          (d.findings_by_status.false_positive || 0) + " falsos positivos"))),
    h("div", { class: "card" }, h("h2", {}, "Achados em aberto por categoria OWASP Top 10"),
      d.open_by_owasp.length ? d.open_by_owasp.map((o) => h("div", { class: "hbar" }, h("span", {}, o.category),
        h("div", { class: "bar" }, h("i", { "data-w": Math.round((100 * o.count) / max) })), h("b", {}, o.count)))
        : h("div", { class: "empty" }, "Nenhum achado em aberto.")),
    h("div", { class: "card" }, h("h2", {}, "Varreduras recentes"), scansTable(d.recent_scans)),
  ];
}

// ---------------------------------------------------------------- targets
async function targetsView() {
  const targets = await api("/targets");
  const rows = targets.map((t) => h("tr", {},
    h("td", {}, h("b", {}, t.name), h("br"), h("span", { class: "muted mono" }, t.base_url)),
    h("td", {}, t.verified ? h("span", { class: "badge ok" }, "Verificado")
      : h("span", { class: "badge warn" }, t.verification_expired ? "Verificação expirada" : "Pendente")),
    h("td", {}, SEV.slice(0, 4).filter((s) => t.open_findings[s]).map((s) =>
      h("span", { class: "badge bg-" + s, title: SEV_LABEL[s] }, t.open_findings[s])), " "),
    h("td", {}, t.schedule === "none" ? "Manual" : (t.schedule === "daily" ? "Diária" : "Semanal")),
    h("td", { class: "right" }, h("div", { class: "row" },
      !t.verified && can("analyst") && h("button", { class: "small primary", onclick: () => verifyDialog(t.id) }, "Verificar"),
      t.verified && can("analyst") && h("button", { class: "small primary", onclick: () => scanDialog(t) }, "Varrer"),
      can("analyst") && h("button", { class: "small", onclick: () => targetSettings(t.id) }, "Configurar"),
      h("a", { href: "#/findings?target_id=" + t.id }, "Achados")))));
  return [
    header("Alvos", "Aplicações que a organização tem autorização para avaliar.",
      can("analyst") && h("button", { class: "primary", onclick: newTargetDialog }, "Novo alvo")),
    h("div", { class: "card" }, table(["Alvo", "Propriedade", "Achados abertos", "Agenda", ""], rows,
      "Nenhum alvo cadastrado.")),
  ];
}

function newTargetDialog() {
  const name = h("input", { required: true, placeholder: "Loja virtual" });
  const url = h("input", { required: true, type: "url", placeholder: "https://www.exemplo.com.br" });
  overlay("modal", h("h2", {}, "Novo alvo"),
    h("p", { class: "muted" }, "Só é possível varrer alvos cuja propriedade for comprovada na próxima etapa."),
    h("form", { onsubmit: run(async () => {
      const t = await api("/targets", { method: "POST", body: { name: name.value, base_url: url.value } });
      toast("Alvo cadastrado. Agora comprove a propriedade.");
      await render();
      verifyDialog(t.id);
    }) }, field("Nome", name), field("URL base", url),
    h("p", {}, " "), h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Cadastrar"),
      h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
}

async function verifyDialog(id) {
  const t = await api("/targets/" + id);
  const v = t.verification;
  const check = (method) => run(async () => {
    const r = await api(`/targets/${id}/verify`, { method: "POST", body: { method } });
    if (r.verified) { toast("Propriedade verificada."); closeOverlay(); render(); } else toast(r.detail, true);
  });
  overlay("drawer", h("h2", {}, "Comprovar propriedade de " + t.name),
    h("p", {}, "Escolha um dos métodos abaixo. A verificação vale por tempo limitado e precisa ser refeita periodicamente."),
    h("h3", {}, "1. Registro DNS (recomendado)"),
    h("p", {}, "Crie um registro TXT em ", h("code", {}, v.dns_txt.record), " com o valor:"), h("pre", {}, v.dns_txt.value),
    h("button", { class: "primary", onclick: check("dns_txt") }, "Verificar DNS"),
    h("h3", {}, "2. Arquivo no site"),
    h("p", {}, "Publique um arquivo de texto em ", h("code", {}, v.http_file.url), " contendo apenas:"), h("pre", {}, v.http_file.content),
    h("button", { class: "primary", onclick: check("http_file") }, "Verificar arquivo"),
    h("h3", {}, "3. Meta tag"),
    h("p", {}, "Inclua no <head> da página inicial:"), h("pre", {}, v.meta_tag.html),
    h("button", { class: "primary", onclick: check("meta_tag") }, "Verificar meta tag"),
    h("p", {}, " "), h("button", { onclick: closeOverlay }, "Fechar"));
}

function scanDialog(t) {
  const profile = h("select", {},
    h("option", { value: "passive" }, "Passiva — apenas navega e observa as respostas"),
    h("option", { value: "standard", selected: true }, "Padrão — também testa parâmetros de leitura (GET)"),
    h("option", { value: "full" }, "Completa — inclui formulários POST que não alteram dados críticos"));
  overlay("modal", h("h2", {}, "Iniciar varredura em " + t.name),
    h("p", { class: "muted" }, "Todas as verificações são de detecção, não destrutivas, e respeitam o limite de " +
      t.max_rps + " requisições por segundo."),
    field("Perfil", profile), h("p", {}, " "),
    h("div", { class: "row" }, h("button", { class: "primary", onclick: run(async () => {
      await api("/scans", { method: "POST", body: { target_id: t.id, profile: profile.value } });
      closeOverlay(); toast("Varredura iniciada."); location.hash = "#/scans"; render();
    }) }, "Iniciar"), h("button", { onclick: closeOverlay }, "Cancelar")));
}

async function targetSettings(id) {
  const t = await api("/targets/" + id);
  const name = h("input", { value: t.name });
  const rps = h("input", { type: "number", min: 1, max: 100, step: 1, value: t.max_rps });
  const excludes = h("textarea", { rows: 3, placeholder: "/admin\n/checkout" });
  excludes.value = t.excludes.join("\n");
  const schedule = h("select", {}, [["none", "Manual"], ["daily", "Diária"], ["weekly", "Semanal"]].map(([v, l]) =>
    h("option", { value: v, selected: t.schedule === v }, l)));
  const sprofile = h("select", {}, Object.entries(PROFILE).map(([v, l]) => h("option", { value: v, selected: t.schedule_profile === v }, l)));
  const hname = h("input", { placeholder: "Authorization" });
  const hvalue = h("input", { placeholder: "Bearer …", type: "password", autocomplete: "off" });
  overlay("drawer", h("h2", {}, "Configurar " + t.name), h("p", { class: "muted mono" }, t.base_url),
    field("Nome", name), field("Limite de requisições por segundo", rps),
    field("Trechos de URL a ignorar (um por linha)", excludes),
    h("div", { class: "grid g2" }, field("Agenda", schedule), field("Perfil agendado", sprofile)),
    h("p", {}, " "),
    h("button", { class: "primary", onclick: run(async () => {
      await api("/targets/" + id, { method: "PATCH", body: { name: name.value, max_rps: Number(rps.value),
        excludes: excludes.value.split("\n").map((s) => s.trim()).filter(Boolean),
        schedule: schedule.value, schedule_profile: sprofile.value } });
      toast("Configurações salvas."); closeOverlay(); render();
    }) }, "Salvar"),
    can("admin") && h("div", {}, h("h3", {}, "Varredura autenticada"),
      h("p", { class: "muted" }, t.has_auth_headers ? "Há credenciais configuradas. Elas ficam criptografadas e nunca são exibidas."
        : "Informe um cabeçalho de sessão de uma conta de teste. Ele fica criptografado e é enviado apenas ao alvo."),
      h("div", { class: "grid g2" }, field("Cabeçalho", hname), field("Valor", hvalue)), h("p", {}, " "),
      h("div", { class: "row" },
        h("button", { onclick: run(async () => {
          if (!hname.value || !hvalue.value) throw new Error("Informe o cabeçalho e o valor");
          await api("/targets/" + id, { method: "PATCH", body: { auth_headers: { [hname.value]: hvalue.value } } });
          toast("Credenciais salvas."); closeOverlay(); render();
        }) }, "Salvar credenciais"),
        t.has_auth_headers && h("button", { class: "danger", onclick: run(async () => {
          await api("/targets/" + id, { method: "PATCH", body: { auth_headers: {} } });
          toast("Credenciais removidas."); closeOverlay(); render();
        }) }, "Remover credenciais"))),
    can("admin") && h("div", {}, h("h3", {}, "Zona de risco"),
      h("button", { class: "danger", onclick: run(async () => {
        if (!confirm("Excluir o alvo e todo o histórico de varreduras e achados?")) return;
        await api("/targets/" + id, { method: "DELETE" });
        toast("Alvo excluído."); closeOverlay(); render();
      }) }, "Excluir alvo")),
    h("p", {}, " "), h("button", { onclick: closeOverlay }, "Fechar"));
}

// ---------------------------------------------------------------- scans
function scansTable(scans) {
  const rows = scans.map((s) => {
    const active = s.status === "queued" || s.status === "running";
    const sum = s.summary || {};
    return h("tr", {},
      h("td", {}, h("b", {}, s.target_name || "—"), h("br"), h("span", { class: "muted" }, PROFILE[s.profile] + " · " + fmt(s.created_at))),
      h("td", {}, h("span", { class: "badge " + ({ completed: "ok", failed: "bad", canceled: "gray" }[s.status] || "warn") }, SCAN_STATUS[s.status]),
        active && h("div", {}, h("div", { class: "bar" }, h("i", { "data-w": s.progress })), h("span", { class: "muted" }, STAGE[s.stage] || "")),
        s.error && h("div", { class: "muted" }, s.error)),
      h("td", {}, s.status === "completed" ? SEV.slice(0, 4).filter((x) => sum[x]).map((x) => h("span", { class: "badge bg-" + x }, sum[x])) : "",
        s.status === "completed" && h("div", { class: "muted" }, (sum.new || 0) + " novos · " + (sum.fixed || 0) + " corrigidos")),
      h("td", {}, s.pages_crawled + " páginas", h("br"), h("span", { class: "muted" }, s.requests_sent + " requisições" +
        (sum.rendered ? " · " + sum.rendered + " renderizadas" : ""))),
      h("td", { class: "right" }, h("div", { class: "row" },
        active && can("analyst") && h("button", { class: "small danger", onclick: run(async () => {
          await api(`/scans/${s.id}/cancel`, { method: "POST" }); toast("Cancelamento solicitado."); render();
        }) }, "Cancelar"),
        !active && h("a", { href: "#/findings?scan_id=" + s.id }, "Achados"),
        !active && ["html", "csv", "sarif", "json"].map((f) => h("button", { class: "small", onclick: run(() => download(s.id, f)) }, f.toUpperCase())))));
  });
  return table(["Alvo", "Situação", "Resultado", "Cobertura", ""], rows, "Nenhuma varredura executada.");
}

async function download(scanId, format) {
  const res = await api(`/scans/${scanId}/report?format=${format}`, { raw: true });
  const url = URL.createObjectURL(await res.blob());
  const a = h("a", { href: url, download: `atalaia-${scanId.slice(0, 8)}.${format}` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

async function scansView() {
  const scans = await api("/scans");
  if (scans.some((s) => s.status === "queued" || s.status === "running")) state.timer = setTimeout(render, 2000);
  return [header("Varreduras", "Histórico e andamento das avaliações."), h("div", { class: "card" }, scansTable(scans))];
}

// ---------------------------------------------------------------- findings
function hashParams() { return new URLSearchParams((location.hash.split("?")[1]) || ""); }

async function findingsView() {
  const p = hashParams();
  if (!p.has("status") && !p.has("scan_id")) p.set("status", "open");
  const data = await api("/findings?" + p.toString());
  const setParam = (k, v) => { const q = hashParams(); if (v) q.set(k, v); else q.delete(k);
    if (k !== "status" && !q.has("status") && !q.has("scan_id")) q.set("status", "open");
    location.hash = "#/findings?" + q.toString(); };
  const q = h("input", { placeholder: "Buscar por título ou URL", value: p.get("q") || "",
    onchange: (e) => setParam("q", e.target.value) });
  const sev = h("select", { onchange: (e) => setParam("severity", e.target.value) }, h("option", { value: "" }, "Todas as severidades"),
    SEV.map((s) => h("option", { value: s, selected: p.get("severity") === s }, SEV_LABEL[s])));
  const st = h("select", { onchange: (e) => setParam("status", e.target.value || "open,fixed,false_positive,accepted_risk") },
    h("option", { value: "" }, "Todas as situações"),
    Object.entries(STATUS_LABEL).map(([v, l]) => h("option", { value: v, selected: p.get("status") === v }, l)));
  const rows = data.items.map((f) => h("tr", { class: "click", tabindex: 0, onclick: () => findingDrawer(f.id),
    onkeydown: (e) => { if (e.key === "Enter") findingDrawer(f.id); } },
    h("td", {}, sevBadge(f.severity)), h("td", {}, h("b", {}, f.title), h("br"), h("span", { class: "muted" }, f.owasp),
      f.confidence === "confirmed" && h("div", {}, h("span", { class: "badge ok" }, "Comprovado"))),
    h("td", { class: "wrap mono" }, f.method + " " + f.url, f.parameter && h("div", { class: "muted" }, "parâmetro: " + f.parameter)),
    h("td", {}, f.target_name), h("td", {}, STATUS_LABEL[f.status]), h("td", {}, fmt(f.last_seen))));
  return [
    header("Achados", data.total + " resultado(s)" + (p.get("scan_id") ? " nesta varredura" : "")),
    h("div", { class: "filters" }, q, sev, st,
      h("button", { onclick: () => { location.hash = "#/findings"; } }, "Limpar filtros")),
    h("div", { class: "card" }, table(["Sev.", "Achado", "Local", "Alvo", "Situação", "Última detecção"], rows,
      "Nenhum achado com estes filtros.")),
  ];
}

async function findingDrawer(id) {
  const f = await api("/findings/" + id);
  const note = h("textarea", { rows: 2, placeholder: "Justificativa (obrigatória para falso positivo e risco aceito)" });
  const set = (status) => run(async () => {
    await api("/findings/" + id, { method: "PATCH", body: { status, note: note.value } });
    toast("Achado atualizado."); closeOverlay(); render();
  });
  overlay("drawer", h("div", { class: "row" }, sevBadge(f.severity), h("span", { class: "badge gray" }, STATUS_LABEL[f.status])),
    h("h2", {}, f.title), h("p", {}, f.description),
    h("dl", {}, h("dt", {}, "Alvo"), h("dd", {}, f.target_name), h("dt", {}, "Local"), h("dd", { class: "mono" }, f.method + " " + f.url),
      f.parameter && [h("dt", {}, "Parâmetro"), h("dd", { class: "mono" }, f.parameter)],
      h("dt", {}, "Classificação"), h("dd", {}, (f.cwe ? "CWE-" + f.cwe + " · " : "") + f.owasp + " · CVSS " + f.cvss),
      h("dt", {}, "Confiança"), h("dd", {}, CONFIDENCE[f.confidence] || f.confidence),
      h("dt", {}, "Histórico"), h("dd", {}, "Primeira detecção em " + fmt(f.first_seen) + "; última em " + fmt(f.last_seen)),
      f.status_note && [h("dt", {}, "Observação"), h("dd", {}, f.status_note)]),
    h("h3", {}, "Evidência"), h("pre", {}, f.evidence),
    h("h3", {}, "Como corrigir"), h("p", {}, f.remediation),
    f.references.length ? [h("h3", {}, "Referências"), f.references.map((r) =>
      h("div", {}, /^https:\/\//.test(r) ? h("a", { href: r, target: "_blank", rel: "noopener noreferrer" }, r) : r))] : null,
    can("analyst") && h("div", {}, h("h3", {}, "Triagem"), note, h("p", {}, " "), h("div", { class: "row" },
      f.status !== "open" && h("button", { onclick: set("open") }, "Reabrir"),
      f.status !== "fixed" && h("button", { onclick: set("fixed") }, "Marcar como corrigido"),
      f.status !== "false_positive" && h("button", { onclick: set("false_positive") }, "Falso positivo"),
      f.status !== "accepted_risk" && h("button", { onclick: set("accepted_risk") }, "Aceitar risco"))),
    h("p", {}, " "), h("button", { onclick: closeOverlay }, "Fechar"));
}

// ---------------------------------------------------------------- team
async function teamView() {
  const [users, keys] = await Promise.all([api("/users"), api("/api-keys")]);
  const roles = state.me.role === "owner" ? ["viewer", "analyst", "admin", "owner"] : ["viewer", "analyst", "admin"];
  const userRows = users.map((u) => {
    const self = state.me.user && state.me.user.id === u.id;
    const locked = self || (u.role === "owner" && state.me.role !== "owner");
    return h("tr", {}, h("td", {}, h("b", {}, u.name), h("br"), h("span", { class: "muted" }, u.email)),
      h("td", {}, locked ? ROLE[u.role] : h("select", { onchange: run(async (e) => {
        await api("/users/" + u.id, { method: "PATCH", body: { role: e.target.value } }); toast("Papel atualizado."); render();
      }) }, roles.map((r) => h("option", { value: r, selected: u.role === r }, ROLE[r])))),
      h("td", {}, u.is_active ? h("span", { class: "badge ok" }, "Ativo") : h("span", { class: "badge gray" }, "Inativo")),
      h("td", {}, u.mfa_enabled ? h("span", { class: "badge ok" }, "Ativa") : h("span", { class: "badge gray" }, "Não configurada")),
      h("td", { class: "right" }, !locked && u.mfa_enabled && h("button", { class: "small", onclick: run(async () => {
        if (!confirm("Redefinir a verificação em duas etapas de " + u.email + "? A pessoa precisará configurá-la de novo.")) return;
        await api("/users/" + u.id + "/mfa/reset", { method: "POST" }); toast("Verificação em duas etapas redefinida."); render();
      }) }, "Redefinir 2 etapas"), " ", !locked && h("button", { class: "small", onclick: run(async () => {
        await api("/users/" + u.id, { method: "PATCH", body: { is_active: !u.is_active } }); render();
      }) }, u.is_active ? "Desativar" : "Reativar")));
  });
  const keyRows = keys.map((k) => h("tr", {}, h("td", {}, h("b", {}, k.name), h("br"), h("span", { class: "muted mono" }, k.prefix + "_…")),
    h("td", {}, ROLE[k.role]), h("td", {}, k.last_used_at ? fmt(k.last_used_at) : "Nunca usada"),
    h("td", { class: "right" }, k.revoked ? h("span", { class: "badge gray" }, "Revogada") : h("button", { class: "small danger", onclick: run(async () => {
      if (!confirm("Revogar esta chave?")) return;
      await api("/api-keys/" + k.id, { method: "DELETE" }); render();
    }) }, "Revogar"))));
  return [
    header("Equipe e chaves de API", "Controle de acesso por papel.",
      h("button", { class: "primary", onclick: newUserDialog }, "Novo usuário"), h("button", { onclick: newKeyDialog }, "Nova chave de API")),
    h("div", { class: "card" }, h("h2", {}, "Usuários"), table(["Usuário", "Papel", "Situação", "Duas etapas", ""], userRows)),
    h("div", { class: "card" }, h("h2", {}, "Política de acesso"),
      h("p", {}, state.me.organization.require_mfa
        ? "A verificação em duas etapas é obrigatória: quem ainda não configurou só consegue acessar a tela de configuração."
        : "A verificação em duas etapas é opcional para os usuários desta organização."),
      state.me.role === "owner" && h("button", { onclick: run(async () => {
        await api("/organization", { method: "PATCH", body: { require_mfa: !state.me.organization.require_mfa } });
        toast("Política atualizada."); await boot();
      }) }, state.me.organization.require_mfa ? "Tornar opcional" : "Exigir de todos os usuários")),
    h("div", { class: "card" }, h("h2", {}, "Chaves de API"),
      h("p", { class: "muted" }, "Use no cabeçalho X-API-Key para integrar varreduras ao pipeline de CI/CD."),
      table(["Chave", "Papel", "Último uso", ""], keyRows, "Nenhuma chave criada.")),
  ];
}

function roleSelect() { return h("select", {}, ["viewer", "analyst", "admin"].map((r) => h("option", { value: r, selected: r === "analyst" }, ROLE[r]))); }

function newUserDialog() {
  const name = h("input", { required: true }), email = h("input", { type: "email", required: true });
  const pw = h("input", { type: "password", required: true, minlength: 12, autocomplete: "new-password" }), role = roleSelect();
  overlay("modal", h("h2", {}, "Novo usuário"), h("form", { onsubmit: run(async () => {
    await api("/users", { method: "POST", body: { name: name.value, email: email.value, password: pw.value, role: role.value } });
    toast("Usuário criado."); closeOverlay(); render();
  }) }, field("Nome", name), field("E-mail", email), field("Senha inicial (mínimo de 12 caracteres)", pw), field("Papel", role),
  h("p", {}, " "), h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Criar"), h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
}

function newKeyDialog() {
  const name = h("input", { required: true, placeholder: "Pipeline de CI" }), role = roleSelect();
  overlay("modal", h("h2", {}, "Nova chave de API"), h("form", { onsubmit: run(async () => {
    const k = await api("/api-keys", { method: "POST", body: { name: name.value, role: role.value } });
    overlay("modal", h("h2", {}, "Chave criada"), h("div", { class: "notice" }, "Copie agora: a chave não será exibida novamente."),
      h("pre", {}, k.key), h("button", { class: "primary", onclick: () => { closeOverlay(); render(); } }, "Já copiei"));
  }) }, field("Nome", name), field("Papel", role), h("p", {}, " "),
  h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Criar"), h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
}

// ---------------------------------------------------------------- account
function qrCanvas(rows) {
  const scale = 4, c = h("canvas", { class: "qr", width: rows.length * scale, height: rows.length * scale,
    role: "img", "aria-label": "Código QR para o aplicativo autenticador" });
  const ctx = c.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, c.width, c.height); ctx.fillStyle = "#000";
  rows.forEach((row, y) => { for (let x = 0; x < row.length; x++) if (row[x] === "1") ctx.fillRect(x * scale, y * scale, scale, scale); });
  return c;
}

function setToken(token) { state.token = token; sessionStorage.setItem("atalaia.token", token); }

function mfaSetupDialog() {
  const pw = h("input", { type: "password", required: true, autocomplete: "current-password" });
  overlay("modal", h("h2", {}, "Ativar verificação em duas etapas"),
    h("p", { class: "muted" }, "Confirme sua senha para gerar a chave do aplicativo autenticador."),
    h("form", { onsubmit: run(async () => {
      const s = await api("/auth/mfa/setup", { method: "POST", body: { password: pw.value } });
      const code = h("input", { required: true, autocomplete: "one-time-code", inputmode: "numeric", maxlength: 8, placeholder: "000000" });
      overlay("modal", h("h2", {}, "Leia o código no aplicativo"),
        h("p", { class: "muted" }, "Use Google Authenticator, Microsoft Authenticator, Authy, 1Password ou outro aplicativo TOTP."),
        s.qr.length ? qrCanvas(s.qr) : null,
        h("p", { class: "muted" }, "Se não puder ler o código, digite esta chave no aplicativo:"), h("pre", { id: "mfa-secret" }, s.secret),
        h("form", { onsubmit: run(async () => {
          const done = await api("/auth/mfa/enable", { method: "POST", body: { code: code.value } });
          setToken(done.token);
          overlay("modal", h("h2", {}, "Guarde os códigos de recuperação"),
            h("div", { class: "notice" }, "Cada código funciona uma única vez e substitui o aplicativo se você perder o aparelho. Eles não serão exibidos novamente."),
            h("pre", { id: "recovery-codes" }, done.recovery_codes.join("\n")),
            h("button", { class: "primary", onclick: run(async () => { closeOverlay(); await boot(); }) }, "Já guardei"));
        }) }, field("Código de 6 dígitos exibido no aplicativo", code), h("p", {}, " "),
        h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Ativar"), h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
    }) }, field("Senha atual", pw), h("p", {}, " "),
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Continuar"), h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
}

function mfaDisableDialog() {
  const pw = h("input", { type: "password", required: true, autocomplete: "current-password" });
  const code = h("input", { required: true, autocomplete: "one-time-code", maxlength: 32 });
  overlay("modal", h("h2", {}, "Desativar verificação em duas etapas"), h("form", { onsubmit: run(async () => {
    const done = await api("/auth/mfa/disable", { method: "POST", body: { password: pw.value, code: code.value } });
    setToken(done.token); closeOverlay(); toast("Verificação em duas etapas desativada."); await boot();
  }) }, field("Senha atual", pw), field("Código do aplicativo ou código de recuperação", code), h("p", {}, " "),
  h("div", { class: "row" }, h("button", { class: "danger", type: "submit" }, "Desativar"), h("button", { type: "button", onclick: closeOverlay }, "Cancelar"))));
}

async function accountView() {
  const u = state.me.user;
  const grants = state.me.mfa_setup_required ? [] : await api("/oauth/grants");
  const grantRows = grants.map((g) => h("tr", {}, h("td", {}, h("b", {}, g.client_name),
      state.me.role === "admin" || state.me.role === "owner" ? h("div", { class: "muted" }, g.user_email) : null),
    h("td", {}, g.role === "analyst" ? "Consultar e agir" : "Somente consultar"),
    h("td", {}, g.last_used_at ? fmt(g.last_used_at) : "Nunca usado"),
    h("td", { class: "right" }, h("button", { class: "small danger", onclick: run(async () => {
      if (!confirm("Desconectar " + g.client_name + "? Ele perde o acesso imediatamente.")) return;
      await api("/oauth/grants/" + g.id, { method: "DELETE" }); toast("Aplicativo desconectado."); render();
    }) }, "Desconectar"))));
  const cur = h("input", { type: "password", required: true, autocomplete: "current-password" });
  const neu = h("input", { type: "password", required: true, minlength: 12, autocomplete: "new-password" });
  return [
    header("Minha conta", u.name + " · " + u.email),
    state.me.mfa_setup_required && h("div", { class: "notice" },
      "Sua organização exige verificação em duas etapas. Ative-a abaixo para liberar o restante do painel."),
    h("div", { class: "card" }, h("h2", {}, "Verificação em duas etapas"),
      h("p", {}, u.mfa_enabled
        ? "Ativa. Além da senha, o login pede um código do seu aplicativo autenticador."
        : "Desativada. Com ela, uma senha vazada não basta para entrar na sua conta."),
      u.mfa_enabled ? h("button", { class: "danger", onclick: mfaDisableDialog }, "Desativar")
        : h("button", { class: "primary", onclick: mfaSetupDialog }, "Ativar verificação em duas etapas")),
    h("div", { class: "card" }, h("h2", {}, "Aplicativos conectados"),
      h("p", { class: "muted" }, "Assistentes de IA (como o Claude) conectados ao Atalaia pelo MCP em " + location.origin + "/mcp. "
        + "Eles agem com o seu usuário, limitados ao nível de acesso que você autorizou."),
      table(["Aplicativo", "Acesso", "Último uso", ""], grantRows, "Nenhum aplicativo conectado.")),
    h("div", { class: "card" }, h("h2", {}, "Alterar senha"), h("form", { onsubmit: run(async () => {
      const done = await api("/auth/change-password", { method: "POST", body: { current_password: cur.value, new_password: neu.value } });
      setToken(done.token); cur.value = ""; neu.value = ""; toast("Senha alterada. As outras sessões foram encerradas.");
    }) }, field("Senha atual", cur), field("Nova senha (mínimo de 12 caracteres)", neu), h("p", {}, " "),
    h("button", { class: "primary", type: "submit" }, "Alterar senha"))),
  ];
}

// ---------------------------------------------------------------- audit
async function auditView() {
  const [logs, chain] = await Promise.all([api("/audit-logs?limit=200"), api("/audit-logs/verify")]);
  const rows = logs.map((a) => h("tr", {}, h("td", {}, fmt(a.created_at)), h("td", {}, a.actor), h("td", { class: "mono" }, a.action),
    h("td", { class: "wrap mono" }, (a.resource_type ? a.resource_type + " " + a.resource_id.slice(0, 8) + " " : "") + (Object.keys(a.details).length ? JSON.stringify(a.details) : "")),
    h("td", { class: "mono" }, a.ip)));
  return [
    header("Trilha de auditoria", "Registro encadeado por hash de todas as ações sensíveis."),
    h("div", { class: "notice" }, chain.valid ? `Integridade verificada: ${chain.entries} registros, cadeia de hash íntegra.`
      : `ATENÇÃO: a cadeia de hash foi quebrada no registro ${chain.broken_at}.`),
    h("div", { class: "card" }, table(["Quando", "Quem", "Ação", "Detalhes", "IP"], rows)),
  ];
}

// ---------------------------------------------------------------- router
const ROUTES = { "#/": dashboardView, "#/targets": targetsView, "#/scans": scansView, "#/findings": findingsView,
  "#/team": teamView, "#/audit": auditView, "#/account": accountView };

let renderSeq = 0;
async function render() {
  clearTimeout(state.timer);
  const seq = ++renderSeq;
  const route = (location.hash || "#/").split("?")[0];
  if (!state.token || !state.me) {
    app.replaceChildren(authView(route === "#/register" ? "register" : "login"));
    return;
  }
  // Until the second factor required by the organization is enrolled, the API refuses everything else.
  const view = state.me.mfa_setup_required ? accountView : (ROUTES[route] || dashboardView);
  let content;
  try { content = await view(); } catch (e) { content = [header("Erro"), h("div", { class: "card" }, e.message)]; }
  if (seq !== renderSeq) return;
  const keepOverlay = document.querySelector(".overlay");
  app.replaceChildren(shell(content));
  // Widths are applied from data attributes because the CSP forbids inline styles.
  app.querySelectorAll("[data-w]").forEach((el) => { el.style.width = el.dataset.w + "%"; });
  if (keepOverlay) document.body.append(keepOverlay);
}

async function boot() {
  if (state.token) {
    try { state.me = await api("/me"); } catch (e) { state.token = null; state.me = null; }
  }
  await render();
}

window.addEventListener("hashchange", () => { closeOverlay(); render(); });
boot();

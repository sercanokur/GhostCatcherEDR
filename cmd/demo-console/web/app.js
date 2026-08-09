const timeline = document.getElementById("timeline");
const healthEl = document.getElementById("health");
const btnHealth = document.getElementById("btn-health");
const btnRunAll = document.getElementById("btn-run-all");
const btnTermClear = document.getElementById("btn-term-clear");
const termEl = document.getElementById("term");
const termTitle = document.getElementById("term-title");

let busy = false;
let seenSeq = 0;

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || res.statusText);
  }
  return res.json();
}

function statusLabel(s) {
  switch (s) {
    case "detected": return "Detected";
    case "missed": return "Not detected";
    case "running": return "Running…";
    case "ok": return "Ready";
    case "error": return "Error";
    default: return "Idle";
  }
}

function appendTermLine(line) {
  if (!line || line.seq <= seenSeq) return;
  seenSeq = line.seq;
  const span = document.createElement("span");
  span.className = "line " + (line.kind || "out");
  span.textContent = (line.text || "") + "\n";
  // Keep blinking cursor at end
  const cursor = termEl.querySelector(".cursor");
  if (cursor) termEl.insertBefore(span, cursor);
  else termEl.appendChild(span);
  termEl.scrollTop = termEl.scrollHeight;
}

function ensureCursor() {
  if (!termEl.querySelector(".cursor")) {
    const c = document.createElement("span");
    c.className = "cursor";
    c.setAttribute("aria-hidden", "true");
    termEl.appendChild(c);
  }
}

function connectTerminal() {
  ensureCursor();
  const es = new EventSource("/api/terminal/stream");
  es.onmessage = (ev) => {
    try {
      appendTermLine(JSON.parse(ev.data));
    } catch (_) { /* ignore */ }
  };
  es.onerror = () => {
    // Browser will retry EventSource automatically.
  };
}

function renderSteps(steps) {
  timeline.innerHTML = "";
  steps.forEach((step, i) => {
    const li = document.createElement("li");
    li.className = "step";
    li.dataset.index = String(step.index);
    li.dataset.status = step.status || "idle";
    li.style.animationDelay = `${i * 40}ms`;

    const head = document.createElement("div");
    head.className = "step-head";
    head.innerHTML = `
      <h2>${escapeHtml(step.title)}</h2>
      <span class="badge ${step.status || "idle"}">${statusLabel(step.status)}</span>
    `;

    const narr = document.createElement("p");
    narr.className = "narration";
    narr.textContent = step.narration || "";

    const actions = document.createElement("div");
    actions.className = "hero-actions";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn step";
    btn.textContent = step.id === "reset" ? "Reset" : "Run step";
    btn.disabled = busy || step.status === "running";
    btn.addEventListener("click", () => runStep(step.id));
    actions.appendChild(btn);

    li.appendChild(head);
    li.appendChild(narr);
    li.appendChild(actions);

    if (step.evidence && step.evidence.length) {
      const box = document.createElement("div");
      box.className = "evidence";
      step.evidence.forEach((ev) => {
        const block = document.createElement("div");
        block.className = "ev-block" + (ev.detected ? "" : " miss");
        const h3 = document.createElement("h3");
        h3.textContent = ev.title || ev.rule_id || "Result";
        const sum = document.createElement("p");
        sum.className = "summary";
        sum.textContent = ev.summary || "";
        block.appendChild(h3);
        block.appendChild(sum);
        if (ev.bullets && ev.bullets.length) {
          const ul = document.createElement("ul");
          ev.bullets.forEach((b) => {
            const liB = document.createElement("li");
            liB.textContent = b;
            ul.appendChild(liB);
          });
          block.appendChild(ul);
        }
        box.appendChild(block);
      });
      li.appendChild(box);
    }

    if (step.error) {
      const err = document.createElement("p");
      err.className = "summary";
      err.style.color = "var(--bad)";
      err.textContent = step.error;
      li.appendChild(err);
    }

    timeline.appendChild(li);
  });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function refresh() {
  const data = await api("/api/steps");
  if (data.target) termTitle.textContent = data.target + " — ssh";
  renderSteps(data.steps || []);
}

async function runStep(id) {
  if (busy) return;
  busy = true;
  setButtons(true);
  try {
    const stepsData = await api("/api/steps");
    const steps = stepsData.steps || [];
    const idx = steps.findIndex((s) => s.id === id);
    if (idx >= 0) {
      steps[idx].status = "running";
      renderSteps(steps);
    }
    await api(`/api/steps/${id}/run`, { method: "POST" });
    await refresh();
  } catch (e) {
    alert(e.message || String(e));
    await refresh();
  } finally {
    busy = false;
    setButtons(false);
  }
}

async function runAll() {
  if (busy) return;
  if (!confirm("Reset lab and run the full kill-chain on the victim?")) return;
  busy = true;
  setButtons(true);
  try {
    await api("/api/run-all", { method: "POST" });
    await refresh();
  } catch (e) {
    alert(e.message || String(e));
    await refresh();
  } finally {
    busy = false;
    setButtons(false);
  }
}

async function checkHealth() {
  try {
    const h = await api("/api/health");
    if (h.target) termTitle.textContent = h.target + " — ssh";
    healthEl.hidden = false;
    healthEl.textContent = JSON.stringify(h, null, 2);
  } catch (e) {
    healthEl.hidden = false;
    healthEl.textContent = String(e.message || e);
  }
}

function setButtons(disabled) {
  btnRunAll.disabled = disabled;
  btnHealth.disabled = disabled;
  timeline.querySelectorAll("button.step").forEach((b) => {
    b.disabled = disabled;
  });
}

btnHealth.addEventListener("click", checkHealth);
btnRunAll.addEventListener("click", runAll);
btnTermClear.addEventListener("click", async () => {
  await api("/api/terminal/clear", { method: "POST" });
  termEl.innerHTML = "";
  seenSeq = 0;
  ensureCursor();
});

connectTerminal();
refresh().catch((e) => {
  timeline.innerHTML = `<li class="step"><p class="narration">${escapeHtml(e.message)}</p></li>`;
});

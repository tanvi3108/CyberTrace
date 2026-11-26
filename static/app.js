let cy = null;

function getSavedState() {
  try {
    return JSON.parse(sessionStorage.getItem("cybertrace_state") || "null");
  } catch {
    return null;
  }
}

function saveState(data) {
  sessionStorage.setItem("cybertrace_state", JSON.stringify(data));
}

function getSelectedStartNode() {
  return sessionStorage.getItem("cybertrace_start_node") || "U001";
}

function setSelectedStartNode(nodeId) {
  sessionStorage.setItem("cybertrace_start_node", nodeId);
}

document.addEventListener("DOMContentLoaded", async () => {
  const page = document.body.dataset.page;

  if (page === "dashboard") {
    await initDashboardPage();
  } else if (page === "graph") {
    await initGraphPage();
  } else if (page === "bfs") {
    await initBfsPage();
  } else if (page === "results") {
    await initResultsPage();
  } else if (page === "report") {
    await initReportPage();
  }
});

// =========================================================
// PAGE 1: INVESTIGATION DASHBOARD
// =========================================================
async function initDashboardPage() {
  const res = await fetch("/api/overview?exclude_gateway=true");
  const data = await res.json();

  document.getElementById("metric-users").textContent = data.metrics.total_users;
  document.getElementById("metric-devices").textContent = data.metrics.connected_devices;
  document.getElementById("metric-suspicious").textContent = data.metrics.suspicious_accounts;
  document.getElementById("metric-investigations").textContent = data.metrics.active_investigations;
  document.getElementById("metric-events").textContent = data.metrics.recent_events_count;

  const tbody = document.getElementById("dashboard-events-tbody");
  tbody.innerHTML = "";

  data.recent_security_events.forEach(ev => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${ev.timestamp}</td>
      <td class="mono red-text"><strong>${ev.user_id}</strong></td>
      <td class="mono yellow-text">${ev.device_id}</td>
      <td class="mono blue-text">${ev.ip_address}</td>
      <td><span class="badge-red">${ev.login_type}</span></td>
      <td><button class="neo-btn yellow-btn mini-btn" onclick="jumpToBfs('${ev.user_id}')">Trace ${ev.user_id} ➔</button></td>
    `;
    tbody.appendChild(tr);
  });
}

window.jumpToBfs = function(userId) {
  setSelectedStartNode(userId);
  window.location.href = "/bfs";
};

// =========================================================
// PAGE 2: NETWORK GRAPH EXPLORER
// =========================================================
async function initGraphPage() {
  const chkGw = document.getElementById("chk-gateway");
  const pill = document.getElementById("selected-node-pill");
  pill.textContent = `Starting Node: ${getSelectedStartNode()}`;

  const loadGraph = async () => {
    const res = await fetch(`/api/overview?exclude_gateway=${chkGw.checked}`);
    const data = await res.json();
    renderCytoscapeGraph(data.graph, true);

    const saved = getSavedState();
    if (saved) {
      applyStaticHighlights(saved);
    }
  };

  chkGw.addEventListener("change", loadGraph);
  await loadGraph();
}

// =========================================================
// PAGE 3: BFS INVESTIGATION MODULE
// =========================================================
async function initBfsPage() {
  const depthSlider = document.getElementById("depth-slider");
  const depthVal = document.getElementById("depth-val");
  depthSlider.addEventListener("input", () => {
    depthVal.textContent = `${depthSlider.value} Hop${depthSlider.value > 1 ? "s" : ""}`;
  });

  const res = await fetch("/api/overview?exclude_gateway=true");
  const overview = await res.json();

  const startSel = document.getElementById("select-start");
  const targetSel = document.getElementById("select-target");

  overview.employees.forEach(emp => {
    startSel.add(new Option(`${emp.user_id} — ${emp.name} (${emp.department}) [${emp.status}]`, emp.user_id));
    targetSel.add(new Option(`${emp.user_id} — ${emp.name}`, emp.user_id));
  });

  overview.graph.nodes
    .filter(n => n.type === "device" && (n.device_type === "Database-Node" || n.device_type === "Jump-Server"))
    .forEach(dev => {
      targetSel.add(new Option(`${dev.id} — ${dev.device_type}`, dev.id));
    });

  startSel.value = getSelectedStartNode();
  targetSel.value = "D150";

  renderCytoscapeGraph(overview.graph, false);

  document.getElementById("btn-run-bfs").addEventListener("click", executeBfsRun);
}

async function executeBfsRun() {
  const startNode = document.getElementById("select-start").value;
  const targetNode = document.getElementById("select-target").value;
  setSelectedStartNode(startNode);

  const payload = {
    start_node: startNode,
    target_node: targetNode,
    max_depth: parseInt(document.getElementById("depth-slider").value, 10),
    exclude_gateway: document.getElementById("chk-gateway").checked,
    start_time: document.getElementById("time-start").value.trim(),
    end_time: document.getElementById("time-end").value.trim()
  };

  const res = await fetch("/api/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!res.ok) {
    alert(data.error || "Investigation failed.");
    return;
  }

  saveState(data);
  renderCytoscapeGraph(data.graph, false);
  animateBfsWavefront(data);
  renderBenchmark(data);
  renderShortestChainBanner(data.shortest_chain, startNode, targetNode);
}

// =========================================================
// PAGE 4: INVESTIGATION RESULTS
// =========================================================
async function initResultsPage() {
  let data = getSavedState();
  if (!data) {
    data = await runDefaultBaselineTrace();
  }

  document.getElementById("discovered-count").textContent = `${data.discovered.length} Entities Discovered`;
  document.getElementById("results-subtitle").textContent =
    `Showing BFS traversal results starting from ${data.start_node} (Max Depth: ${data.max_depth} Hops).`;

  const tbody = document.getElementById("results-tbody");
  tbody.innerHTML = "";

  data.discovered.forEach(item => {
    const tr = document.createElement("tr");
    const clsClass = item.level === 0 ? "tag-source" : "tag-exposed";
    tr.innerHTML = `
      <td class="mono blue-text">Level ${item.level}</td>
      <td class="mono"><strong>${item.label}</strong></td>
      <td>${item.type.toUpperCase()}</td>
      <td class="${clsClass}">${item.classification}</td>
      <td class="mono">${item.timestamp}</td>
      <td class="mono yellow-text">${item.chain.join(" ➔ ")}</td>
    `;
    tbody.appendChild(tr);
  });
}

// =========================================================
// PAGE 5: REPORT GENERATION
// =========================================================
async function initReportPage() {
  let d = getSavedState();
  if (!d) {
    d = await runDefaultBaselineTrace();
  }

  document.getElementById("rep-start").textContent = d.start_node;
  document.getElementById("rep-total").textContent = `${d.discovered.length} Entities (Depth ≤ ${d.max_depth})`;
  document.getElementById("rep-order").textContent = d.bfs.traversal_order.join(" -> ");

  const lines = [
    "==========================================================================",
    "        CYBERTRACE // FORENSIC CYBERATTACK INVESTIGATION REPORT",
    "==========================================================================",
    `Starting Compromised Entity : ${d.start_node}`,
    `Total Discovered Nodes      : ${d.discovered.length}`,
    `Search Algorithm            : Manual Breadth-First Search (FIFO Queue)`,
    `BFS Execution Latency       : ${d.bfs.execution_time_ms} ms`,
    "",
    "--- BFS TRAVERSAL ORDER ---",
    d.bfs.traversal_order.join(" -> "),
    "",
    "--- LAYER-BY-LAYER WAVEFRONT ---",
    ...Object.entries(d.bfs.layers).map(([lvl, nodes]) => `Level ${lvl}: ${nodes.join(", ")}`),
    "",
    "--- RECONSTRUCTED CONNECTION CHAINS ---",
    ...d.discovered.map(item => `[Level ${item.level} | ${item.classification}] ${item.chain.join(" -> ")} (${item.timestamp})`),
    "",
    "--- INVESTIGATION SUMMARY ---",
    `Starting from confirmed compromised identity ${d.start_node}, CyberTrace traced`,
    `${d.discovered.length - 1} potentially exposed downstream accounts, endpoints, and IP relays`,
    `across ${Object.keys(d.bfs.layers).length - 1} traversal hops. Immediate credential revocation and`,
    `forensic triage are recommended for all Level >= 1 entities in the chain.`,
    "=========================================================================="
  ];

  const reportText = lines.join("\n");
  document.getElementById("report-content").textContent = reportText;

  document.getElementById("btn-download-txt").addEventListener("click", () => {
    const blob = new Blob([reportText], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `CyberTrace_Report_${d.start_node}.txt`;
    a.click();
  });
}

async function runDefaultBaselineTrace() {
  const res = await fetch("/api/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      start_node: getSelectedStartNode(),
      target_node: "D150",
      max_depth: 8,
      exclude_gateway: true
    })
  });
  const data = await res.json();
  saveState(data);
  return data;
}

// =========================================================
// CYTOSCAPE GRAPH RENDERER (BLACK, RED, YELLOW, BABY BLUE)
// =========================================================
function renderCytoscapeGraph(graphData, allowNodeSelection) {
  const elements = [];

  graphData.nodes.forEach(n => {
    elements.push({
      data: { id: n.id, label: n.id, fullLabel: n.label, type: n.type }
    });
  });

  graphData.edges.forEach(e => {
    elements.push({
      data: { id: e.id, source: e.source, target: e.target }
    });
  });

  cy = cytoscape({
    container: document.getElementById("cy"),
    elements: elements,
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "color": "#f1f5f9",
          "font-size": "10px",
          "font-family": "JetBrains Mono, monospace",
          "text-valign": "bottom",
          "text-margin-y": "5px",
          "width": 25,
          "height": 25,
          "border-width": 1.5,
          "border-color": "rgba(255,255,255,0.25)",
          "transition-property": "background-color, border-color, width, height",
          "transition-duration": "0.35s"
        }
      },
      {
        selector: 'node[type="employee"]',
        style: { "shape": "ellipse", "background-color": "#7dd3fc" } // Baby Blue
      },
      {
        selector: 'node[type="device"]',
        style: { "shape": "round-rectangle", "background-color": "#ffd147" } // Electric Yellow
      },
      {
        selector: 'node[type="ip"]',
        style: { "shape": "diamond", "background-color": "#38bdf8", "width": 22, "height": 22 }
      },
      {
        selector: "edge",
        style: {
          "width": 1.4,
          "line-color": "rgba(125, 211, 252, 0.22)",
          "curve-style": "bezier"
        }
      },
      {
        selector: ".patient-zero",
        style: {
          "background-color": "#ff3b5c", // Crimson Red
          "border-color": "#ffffff",
          "border-width": 3,
          "width": 38,
          "height": 38
        }
      },
      {
        selector: ".bfs-discovered",
        style: {
          "background-color": "#ffd147", // Electric Yellow
          "border-color": "#ff3b5c",
          "border-width": 2.5,
          "width": 31,
          "height": 31
        }
      },
      {
        selector: ".bfs-edge",
        style: {
          "width": 3,
          "line-color": "#ffd147"
        }
      },
      {
        selector: ".shortest-chain",
        style: {
          "background-color": "#ff3b5c",
          "border-color": "#7dd3fc",
          "border-width": 3.5,
          "line-color": "#ff3b5c",
          "width": 4
        }
      }
    ],
    layout: {
      name: "cose",
      animate: false,
      nodeRepulsion: 5500,
      idealEdgeLength: 65
    }
  });

  if (allowNodeSelection) {
    cy.on("tap", "node", evt => {
      const id = evt.target.id();
      const type = evt.target.data("type");
      if (type === "employee") {
        setSelectedStartNode(id);
        document.getElementById("selected-node-pill").textContent = `Starting Node: ${id}`;
        document.getElementById("graph-status-text").textContent =
          `Selected ${evt.target.data("fullLabel")} as Starting Node — click "Trace Selected Node in BFS".`;
      } else {
        document.getElementById("graph-status-text").textContent =
          `Entity Info: ${evt.target.data("fullLabel")} (Select an Employee circle as Starting Node).`;
      }
    });
  }
}

function applyStaticHighlights(data) {
  Object.entries(data.bfs.layers).forEach(([lvlStr, nodes]) => {
    const lvl = Number(lvlStr);
    nodes.forEach(nid => {
      const ele = cy.getElementById(nid);
      if (lvl === 0) ele.addClass("patient-zero");
      else {
        ele.addClass("bfs-discovered");
        const par = data.bfs.parent[nid];
        if (par) {
          cy.getElementById(`${par}__${nid}`).addClass("bfs-edge");
          cy.getElementById(`${nid}__${par}`).addClass("bfs-edge");
        }
      }
    });
  });
}

function animateBfsWavefront(data) {
  const layers = data.bfs.layers;
  const parentMap = data.bfs.parent;
  const levelKeys = Object.keys(layers).map(Number).sort((a, b) => a - b);
  const banner = document.getElementById("layer-status");

  levelKeys.forEach((lvl, idx) => {
    setTimeout(() => {
      const nodesInLayer = layers[lvl];
      banner.textContent = `BFS Wavefront Level ${lvl}: Discovered [${nodesInLayer.join(", ")}]`;

      nodesInLayer.forEach(nid => {
        const nodeEle = cy.getElementById(nid);
        if (lvl === 0) {
          nodeEle.addClass("patient-zero");
        } else {
          nodeEle.addClass("bfs-discovered");
          const par = parentMap[nid];
          if (par) {
            cy.getElementById(`${par}__${nid}`).addClass("bfs-edge");
            cy.getElementById(`${nid}__${par}`).addClass("bfs-edge");
          }
        }
      });

      if (idx === levelKeys.length - 1 && data.shortest_chain.length > 1) {
        for (let i = 0; i < data.shortest_chain.length; i++) {
          const curr = data.shortest_chain[i];
          cy.getElementById(curr).addClass("shortest-chain");
          if (i > 0) {
            const prev = data.shortest_chain[i - 1];
            cy.getElementById(`${prev}__${curr}`).addClass("shortest-chain");
            cy.getElementById(`${curr}__${prev}`).addClass("shortest-chain");
          }
        }
      }
    }, idx * 550);
  });
}

function renderBenchmark(data) {
  const box = document.getElementById("benchmark-box");
  box.innerHTML = `
    <h4>BFS vs. DFS Viva Telemetry</h4>
    <p><strong class="yellow-text">BFS (FIFO Queue):</strong> Found <b>${data.bfs.visited.length}</b> nodes in <b>${data.bfs.execution_time_ms} ms</b>. Guarantees shortest hop path.</p>
    <p style="margin-top:5px;"><strong class="blue-text">DFS (LIFO Stack):</strong> Found <b>${data.dfs_comparison.visited_count}</b> nodes in <b>${data.dfs_comparison.execution_time_ms} ms</b>. Depth-first order; no shortest-path guarantee.</p>
  `;
}

function renderShortestChainBanner(chain, start, target) {
  const banner = document.getElementById("shortest-path-banner");
  if (!target) {
    banner.classList.add("hidden");
    return;
  }
  banner.classList.remove("hidden");
  if (chain && chain.length > 0) {
    banner.textContent = `✦ Shortest Connection Chain (${start} ➔ ${target} | ${chain.length - 1} Hops): ${chain.join(" ➔ ")}`;
  } else {
    banner.textContent = `✦ No connection chain found between ${start} and ${target} within selected depth/time window.`;
  }
}
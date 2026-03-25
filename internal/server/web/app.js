async function boot() {
  const response = await fetch("/api/topology");
  const topology = await response.json();
  renderSummary(topology);
  renderMeta(topology);
  renderFindings(topology.findings || []);
  renderNotes(topology.notes || []);
  renderDiagram(topology.subnets || []);
}

function renderSummary(topology) {
  const entries = [
    ["Hosts", topology.summary.hosts],
    ["Subnets", topology.summary.subnets],
    ["Open ports", topology.summary.openPorts],
    ["Findings", topology.summary.findings],
  ];

  document.getElementById("summary").innerHTML = entries.map(([label, value]) => `
    <div class="metric">
      <strong>${value}</strong>
      <span>${label}</span>
    </div>
  `).join("");
}

function renderMeta(topology) {
  const stamp = new Date(topology.generatedAt).toLocaleString();
  document.getElementById("meta").textContent = `${topology.profile} profile • ${stamp}`;
}

function renderFindings(findings) {
  const root = document.getElementById("findings");
  if (!findings.length) {
    root.innerHTML = `<div class="finding"><h3>No findings</h3><p>No MikroTik bridge/VLAN issues were detected in the current snapshot.</p></div>`;
    return;
  }

  root.innerHTML = findings.map((finding) => `
    <article class="finding">
      <span class="severity ${finding.severity}">${finding.severity}</span>
      <h3>${escapeHTML(finding.title)}</h3>
      <p>${escapeHTML(finding.summary)}</p>
      ${finding.recommendation ? `<p><strong>Fix:</strong> ${escapeHTML(finding.recommendation)}</p>` : ""}
      ${finding.evidence?.length ? `<p><strong>Evidence:</strong> ${finding.evidence.map(escapeHTML).join(" • ")}</p>` : ""}
    </article>
  `).join("");
}

function renderNotes(notes) {
  const root = document.getElementById("notes");
  root.innerHTML = notes.map((note) => `<li>${escapeHTML(note)}</li>`).join("");
}

function renderDiagram(subnets) {
  const canvas = document.getElementById("canvas");
  const svg = document.getElementById("links");
  const positions = new Map();
  const nodes = [];
  const links = [];

  let width = 980;
  let height = Math.max(720, subnets.length * 250);

  subnets.forEach((subnet, subnetIndex) => {
    const baseY = 110 + subnetIndex * 240;
    const subnetNode = {
      id: subnet.id,
      x: 450,
      y: baseY,
      type: "subnet",
      title: subnet.cidr,
      detail: subnet.gateway ? `gateway ${subnet.gateway}` : "no gateway inferred",
    };
    nodes.push(subnetNode);
    positions.set(subnet.id, subnetNode);

    if (subnet.gateway) {
      const gatewayID = `gateway:${subnet.gateway}`;
      if (!positions.has(gatewayID)) {
        const gatewayNode = {
          id: gatewayID,
          x: 790,
          y: baseY,
          type: "gateway",
          title: subnet.gateway,
          detail: "default gateway",
        };
        nodes.push(gatewayNode);
        positions.set(gatewayID, gatewayNode);
      }
      links.push([subnet.id, gatewayID]);
    }

    subnet.hosts.forEach((host, hostIndex) => {
      const row = Math.floor(hostIndex / 2);
      const col = hostIndex % 2;
      const hostNode = {
        id: host.id,
        x: 160 + col * 190,
        y: baseY - 50 + row * 110,
        type: "host",
        title: host.hostname || host.ip,
        detail: host.osFamily || host.deviceType || host.status || "host",
        ports: (host.ports || []).slice(0, 4).map((port) => `${port.number}/${port.protocol} ${port.service || port.state}`),
      };
      nodes.push(hostNode);
      positions.set(host.id, hostNode);
      links.push([host.id, subnet.id]);
      height = Math.max(height, hostNode.y + 180);
    });
  });

  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", width);
  svg.setAttribute("height", height);

  canvas.innerHTML = nodes.map((node) => `
    <article class="node ${node.type}" style="left:${node.x}px; top:${node.y}px">
      <h3>${escapeHTML(node.title)}</h3>
      <p>${escapeHTML(node.detail)}</p>
      ${node.ports?.length ? `<ul>${node.ports.map((entry) => `<li>${escapeHTML(entry)}</li>`).join("")}</ul>` : ""}
    </article>
  `).join("");

  svg.innerHTML = links.map(([fromID, toID]) => {
    const from = positions.get(fromID);
    const to = positions.get(toID);
    return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line>`;
  }).join("");
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

boot().catch((error) => {
  document.body.innerHTML = `<pre>${escapeHTML(error.stack || error.message || String(error))}</pre>`;
});

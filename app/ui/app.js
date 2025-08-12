/* app/ui/app.js */
console.log('[ui] script loaded');

let cy;
let progressTimer = null;

/* ---------------------
   Warnings helper
---------------------- */
function pushWarning(msg) {
  const w = document.getElementById('warnings');
  if (!w) return;
  const a = document.createElement('sl-alert');
  a.variant = 'warning';
  a.closable = true;
  a.open = true;                       // ensure visible
  a.innerText = String(msg);
  w.appendChild(a);
  const det = [...document.querySelectorAll('sl-details')].find(d => d.getAttribute('summary') === 'Warnings');
  if (det) det.setAttribute('open', '');
}

window.addEventListener('error', e => {
  console.error('[ui] window error:', e.error || e.message || e);
  pushWarning(e.error || e.message || e);
});
window.addEventListener('unhandledrejection', e => {
  console.error('[ui] unhandledrejection:', e.reason);
  pushWarning(e.reason);
});

/* ---------------------
   Icons (safe if missing)
---------------------- */
const ICONS = {
  vpc: '/ui/icons/vpc.svg',
  subnet: '/ui/icons/subnet.svg',
  security_group: '/ui/icons/security-group.svg',
  route_table: '/ui/icons/route-table.svg',
  igw: '/ui/icons/internet-gateway.svg',
  nat_gateway: '/ui/icons/nat-gateway.svg',
  eni: '/ui/icons/eni.svg',
  instance: '/ui/icons/ec2-instance.svg',
  load_balancer: '/ui/icons/alb.svg',
  target_group: '/ui/icons/target-group.svg',
  lambda: '/ui/icons/lambda.svg',
  api_gw_v2: '/ui/icons/api-gateway.svg',
  s3_bucket: '/ui/icons/s3.svg',
  sns_topic: '/ui/icons/sns.svg',
  sqs_queue: '/ui/icons/sqs.svg',
  dynamodb_table: '/ui/icons/dynamodb.svg',
  rds_instance: '/ui/icons/rds.svg',
  eks_cluster: '/ui/icons/eks.svg',
  ecs_cluster: '/ui/icons/ecs.svg',
  ecs_service: '/ui/icons/ecs-service.svg',
  eventbridge_bus: '/ui/icons/eventbridge.svg',
  eventbridge_rule: '/ui/icons/eventbridge-rule.svg',
  kinesis: '/ui/icons/kinesis.svg',
  cloudfront: '/ui/icons/cloudfront.svg',
  custom_origin: '/ui/icons/custom-origin.svg',
  cidr: '/ui/icons/cidr.svg',
  external: '/ui/icons/internet.svg',
  kms: '/ui/icons/kms.svg',
  secret: '/ui/icons/secrets-manager.svg',
  ssmparam: '/ui/icons/ssm.svg',
  integration: '/ui/icons/integration.svg',
  api_gw_v2_route: '/ui/icons/api-gateway-route.svg'
};

/* ---------------------
   Containers (pale fills)
---------------------- */
const CONTAINER_COLOR = {
  vpc:         { fill: 'rgba(16, 185, 129, 0.06)',  border: '#10b981' },
  subnet:      { fill: 'rgba(59, 130, 246, 0.06)',  border: '#3b82f6' },
  eks_cluster: { fill: 'rgba(245, 158, 11, 0.06)',  border: '#f59e0b' },
  ecs_cluster: { fill: 'rgba(147, 51, 234, 0.06)',  border: '#9333ea' },
  rds_cluster: { fill: 'rgba(99, 102, 241, 0.06)',  border: '#6366f1' }
};

/* ---------------------
   Styles
---------------------- */
const NODE_STYLES = [
  { selector: 'node', style: {
      'label': 'data(label)',
      'font-size': 11,
      'text-wrap': 'wrap',
      'text-max-width': 160,
      'background-color': '#ffffff',
      'shape': 'round-rectangle',
      'border-width': 1,
      'border-color': '#e5e7eb',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'color':'#111827',
      'z-index-compare': 'manual',
      'z-index': 1
  }},
  { selector: 'node.has-icon', style: {
      'background-image': 'data(icon)',
      'background-fit': 'contain',
      'background-clip': 'node',
      'background-opacity': 1,
      'background-width': '80%',
      'background-height': '80%',
      'background-position-x': '50%',
      'background-position-y': '40%'
  }},
  { selector: 'node.container', style: {
      'background-opacity': 1,
      'padding': 16,
      'text-valign': 'top',
      'text-halign': 'left',
      'text-margin-x': 6,
      'text-margin-y': 6,
      'border-width': 2,
      'background-image': 'none',
      'z-index-compare': 'manual',
      'z-index': 0
  }},
  { selector: 'node.container-vpc',         style: { 'background-color': CONTAINER_COLOR.vpc.fill,        'border-color': CONTAINER_COLOR.vpc.border } },
  { selector: 'node.container-subnet',      style: { 'background-color': CONTAINER_COLOR.subnet.fill,     'border-color': CONTAINER_COLOR.subnet.border } },
  { selector: 'node.container-eks_cluster', style: { 'background-color': CONTAINER_COLOR.eks_cluster.fill,'border-color': CONTAINER_COLOR.eks_cluster.border } },
  { selector: 'node.container-ecs_cluster', style: { 'background-color': CONTAINER_COLOR.ecs_cluster.fill,'border-color': CONTAINER_COLOR.ecs_cluster.border } },
  { selector: 'node.container-rds_cluster', style: { 'background-color': CONTAINER_COLOR.rds_cluster.fill,'border-color': CONTAINER_COLOR.rds_cluster.border } },

  { selector: 'node:selected', style: { 'border-color': '#111827', 'border-width': 3 } },

  { selector: 'node[severity = "high"], node.issue', style: {
      'border-color': '#ef4444',
      'border-width': 3
  }},
];

const EDGE_STYLES = [
  { selector: 'edge', style: {
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.9,
      'width': 2,
      'label': 'data(label)',
      'font-size': 9,
      'color':'#111827'
  }},
  { selector: 'edge[category = "resource"]', style: { 'line-color': '#2563eb', 'target-arrow-color': '#2563eb' } },
  { selector: 'edge[category = "network"]',  style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316' } },
  { selector: 'edge[category = "data"]',     style: { 'line-color': '#0ea5e9', 'target-arrow-color': '#0ea5e9', 'line-style': 'dotted' } },
  { selector: 'edge[derived = "true"]',      style: { 'line-style': 'dashed' } },
  { selector: 'edge[type = "attach"], edge[type = "assoc"]', style: { 'opacity': 0.45 } },
  { selector: 'edge:selected', style: { 'width': 3 } },
  { selector: 'edge[severity = "high"], edge.issue', style: {
      'line-color': '#ef4444',
      'target-arrow-color': '#ef4444',
      'width': 3
  }},
];

/* ---------------------
   Plugins
---------------------- */
function registerCytoscapePlugins() {
  try { if (window.cytoscapeCoseBilkent) cytoscape.use(window.cytoscapeCoseBilkent); } catch {}
  try { if (window.cytoscapeMinimap) cytoscape.use(window.cytoscapeMinimap); } catch {}
  try { if (window.cytoscapeSvg) cytoscape.use(window.cytoscapeSvg); } catch {}
}

/* ---------------------
   Ensure Findings container exists
---------------------- */
function ensureFindingsContainer() {
  let el = document.getElementById('findings') ||
           document.getElementById('findings-list') ||
           document.querySelector('.findings');
  if (el) return el;

  // Create one next to #details (left sidebar), so it’s always visible
  const details = document.getElementById('details');
  const host = details && details.parentElement ? details.parentElement : document.body;

  el = document.createElement('div');
  el.id = 'findings';
  el.style.marginTop = '12px';
  el.innerHTML = '<div class="muted">No findings.</div>';
  host.appendChild(el);
  console.warn('[ui] Created #findings container automatically (was missing).');
  return el;
}

/* ---------------------
   Legend
---------------------- */
function legend() {
  const items = [
    ['VPC (container)', CONTAINER_COLOR.vpc.border],
    ['Subnet (container)', CONTAINER_COLOR.subnet.border],
    ['Resource edges', '#2563eb'],
    ['Network edges', '#f97316'],
    ['Data/invoke edges', '#0ea5e9 (dotted)'],
    ['Derived', 'dashed'],
    ['Issues (High)', '#ef4444']
  ];
  const el = document.getElementById('legend');
  if (!el) return;
  el.innerHTML = '';
  for (const [name, color] of items) {
    const row = document.createElement('div');
    row.className = 'legend-row';
    const sw = document.createElement('span');
    sw.className = 'swatch';
    if (color === 'dashed') {
      sw.style.border = '1px dashed #9ca3af';
      sw.style.background = 'transparent';
    } else {
      sw.style.background = String(color).split(' ')[0];
    }
    row.appendChild(sw);
    row.appendChild(document.createTextNode(name));
    el.appendChild(row);
  }
}

/* ---------------------
   Warnings / Findings / Details
---------------------- */
function renderWarnings(list) {
  const el = document.getElementById('warnings');
  if (!el) return;
  el.innerHTML = '';
  (list || []).forEach(w => {
    const a = document.createElement('sl-alert');
    a.variant = 'warning';
    a.closable = true;
    a.open = true;                        // <-- make visible
    a.innerText = String(w);
    el.appendChild(a);
  });
  if ((list || []).length) {
    const det = [...document.querySelectorAll('sl-details')].find(d => d.getAttribute('summary') === 'Warnings');
    if (det) det.setAttribute('open', '');
  }
}

// Map backend severities to Shoelace variants
function slVariantForSeverity(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'HIGH' || s === 'CRITICAL' || s === 'DANGER') return 'danger';
  if (s === 'MEDIUM' || s === 'WARN' || s === 'WARNING') return 'warning';
  if (s === 'LOW' || s === 'NEUTRAL') return 'neutral';
  return 'primary'; // INFO or unknown
}

function renderFindings(list) {
  const el = ensureFindingsContainer();
  el.innerHTML = '';
  const arr = Array.isArray(list) ? list : [];
  if (!arr.length) {
    el.innerHTML = '<div class="muted">No findings.</div>';
    return;
  }
  for (const f of arr) {
    const a = document.createElement('sl-alert');
    a.variant = slVariantForSeverity(f.severity);  // <-- valid variant
    a.closable = true;
    a.open = true;                                  // <-- show alert
    a.innerText = `[${f.severity || 'INFO'}] ${f.title || ''}${f.detail ? ': ' + f.detail : ''}`;
    el.appendChild(a);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
}

function renderDetails(data) {
  const el = document.getElementById('details');
  if (!el) return;
  const links = (data?.details && Array.isArray(data.details.links)) ? data.details.links : [];
  let html = '';
  if (links.length) {
    html += '<div style="margin-bottom:8px"><strong>Downloads</strong><ul style="margin:6px 0 10px 18px">';
    for (const l of links) {
      const t = String(l.title || 'download');
      const href = String(l.href || '#');
      html += `<li><a href="${href}" target="_blank" rel="noopener">${escapeHtml(t)}</a></li>`;
    }
    html += '</ul></div>';
  }
  html += `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  el.innerHTML = html;
}

/* ---------------------
   Findings helpers
---------------------- */
function indexFindings(findings) {
  const map = {};
  if (!Array.isArray(findings)) return map;
  for (const f of findings) {
    const id = f && f.id;
    if (!id) continue;
    if (!map[id]) map[id] = [];
    map[id].push(f);
  }
  return map;
}

function getFindingsForElement(d) {
  if (!d) return [];
  // 1) inline
  if (Array.isArray(d.findings) && d.findings.length) return d.findings;
  if (Array.isArray(d.issues) && d.issues.length) return d.issues;

  const id = d.id;
  const all = Array.isArray(window.lastFindings) ? window.lastFindings : [];

  // 2) server-supplied index
  const map = window.findingsById || {};
  if (id && map[id] && map[id].length) return map[id];

  // 3) client scan
  if (id) {
    const direct = all.filter(f => f && f.id === id);
    if (direct.length) return direct;
  }

  // 4) synthetic if visually flagged but no text finding
  const flagged = (typeof d.severity === 'string' && d.severity.toLowerCase() === 'high');
  let hasIssueClass = false;
  try {
    const coll = cy && id ? cy.getElementById(id) : null;
    if (coll) {
      const present = (typeof coll.nonempty === 'function') ? coll.nonempty() :
                      (typeof coll.size === 'function') ? (coll.size() > 0) :
                      (typeof coll.length === 'number' ? coll.length > 0 : true);
      if (present) hasIssueClass = coll.hasClass('issue') || coll.hasClass('high');
    }
  } catch {}

  if (flagged || hasIssueClass) {
    return [{
      id: id || '(unknown)',
      type: d.type || 'resource',
      severity: 'HIGH',
      title: 'Security issue flagged',
      detail: 'This element is highlighted as risky, but no detailed finding text was attached. Ensure the backend returns findings_by_id or inline findings for this element.',
      region: d.region,
      label: d.label
    }];
  }
  return [];
}

/* ---------------------
   Element processing
---------------------- */
function markContainers(elements) {
  const parentIds = new Set(
    (elements || [])
      .filter(el => el && el.data && el.data.parent)
      .map(el => el.data.parent)
  );
  return (elements || []).map(el => {
    if (!el || !el.data || el.group !== 'nodes') return el;
    const id = el.data.id;
    if (!id || !parentIds.has(id)) return el;
    const t = (el.data.type || '').trim();
    const cls = (el.classes || '').trim();
    const containerCls = ['container', t ? `container-${t}` : null].filter(Boolean).join(' ');
    el.classes = (cls ? cls + ' ' : '') + containerCls;
    if (el.data.icon) delete el.data.icon;
    el.classes = el.classes.replace(/\bhas-icon\b/g, '').trim();
    return el;
  });
}

function injectIcons(elements) {
  return (elements || []).map(el => {
    if (!el || !el.data || el.group !== 'nodes') return el;
    const isContainer = /\bcontainer\b/.test(el.classes || '');
    if (isContainer) {
      if ('icon' in el.data) delete el.data.icon;
      el.classes = (el.classes || '').replace(/\bhas-icon\b/g, '').trim();
      return el;
    }
    const t = el.data.type;
    const icon = ICONS[t];
    if (icon) {
      el.data.icon = icon;
      const cls = (el.classes || '').trim();
      el.classes = (cls ? cls + ' ' : '') + 'has-icon';
    } else {
      if (!el.data.icon) delete el.data.icon;
      el.classes = (el.classes || '').replace(/\bhas-icon\b/g, '').trim();
    }
    return el;
  });
}

function sanitizeElements(elements) {
  const nodes = [], edges = [];
  for (const el of elements || []) {
    if (!el || !el.data) continue;
    const isEdge = !!(el.data.source || el.data.target) || el.group === 'edges';
    if (isEdge) edges.push(el); else nodes.push(el);
  }
  const nodeMap = new Map();
  for (const n of nodes) {
    const id = n?.data?.id;
    if (!id || nodeMap.has(id)) continue;
    nodeMap.set(id, n);
  }
  const nodeIds = new Set(nodeMap.keys());
  const edgeMap = new Map();
  let dropped = 0;
  for (const e of edges) {
    const d = e.data || {};
    if (!d.source || !d.target || !nodeIds.has(d.source) || !nodeIds.has(d.target)) { dropped++; continue; }
    const eid = d.id || `${d.source}->${d.target}`;
    if (!edgeMap.has(eid)) edgeMap.set(eid, e);
  }
  const cleaned = [...nodeMap.values(), ...edgeMap.values()];
  if (dropped > 0) {
    console.warn('[ui] filtered invalid edges:', dropped);
    pushWarning(`Filtered ${dropped} edges referencing missing nodes. Check ID consistency.`);
  }
  return cleaned;
}

/* ---------------------
   Progress UI
---------------------- */
function ensureProgressBar() {
  let wrap = document.getElementById('progress-wrap');
  if (wrap) return wrap;
  wrap = document.createElement('div');
  wrap.id = 'progress-wrap';
  wrap.style.position = 'absolute';
  wrap.style.left = '360px';
  wrap.style.right = '0';
  wrap.style.top = '0';
  wrap.style.padding = '10px 16px 0 16px';
  wrap.style.pointerEvents = 'none';
  wrap.style.zIndex = '9999';

  const inner = document.createElement('div');
  inner.style.maxWidth = '800px';
  inner.style.margin = '0 auto';
  inner.style.pointerEvents = 'auto';

  const bar = document.createElement('sl-progress-bar');
  bar.id = 'progress-bar';
  bar.style.width = '100%';
  bar.value = 0;
  bar.setAttribute('label', 'Starting…');

  inner.appendChild(bar);
  wrap.appendChild(inner);
  document.body.appendChild(wrap);
  return wrap;
}
function showProgress() {
  const wrap = ensureProgressBar();
  wrap.style.display = 'block';
  const bar = document.getElementById('progress-bar');
  if (bar) { bar.value = 0; bar.setAttribute('label', 'Starting…'); }
}
function hideProgress() {
  const wrap = document.getElementById('progress-wrap');
  if (wrap) wrap.style.display = 'none';
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
}
function newRid() {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  buf[6] = (buf[6] & 0x0f) | 0x40;
  buf[8] = (buf[8] & 0x3f) | 0x80;
  const hex = [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.substr(0,8)}-${hex.substr(8,4)}-${hex.substr(12,4)}-${hex.substr(16,4)}-${hex.substr(20)}`;
}
async function pollProgress(rid) {
  try {
    const res = await fetch(`/progress?rid=${encodeURIComponent(rid)}`, { cache: 'no-store' });
    if (!res.ok) return;
    const js = await res.json();
    const bar = document.getElementById('progress-bar');
    if (!bar) return;
    const total = Math.max(1, Number(js.total || 1));
    const current = Math.min(total, Number(js.current || 0));
    const pct = Math.round((current / total) * 100);
    bar.value = pct;
    const stage = String(js.stage || 'Enumerating…');
    bar.setAttribute('label', `${stage} (${current}/${total})`);
    if (js.done) {
      bar.setAttribute('label', `Completed (${total}/${total})`);
      setTimeout(hideProgress, 600);
    }
  } catch (e) {
    // ignore
  }
}

/* ---------------------
   API
---------------------- */
async function postEnumerate(rid) {
  const ak = (document.getElementById('ak')?.value || '').trim();
  const sk = (document.getElementById('sk')?.value || '').trim();
  const payload = { access_key_id: ak, secret_access_key: sk, rid };
  const res = await fetch('/enumerate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

/* ---------------------
   Init Cytoscape
---------------------- */
function initCySafe() {
  console.log('[ui] initCy');
  if (!window.cytoscape) throw new Error('Cytoscape failed to load.');
  const container = document.getElementById('cy');
  if (!container) throw new Error('#cy container not found');

  registerCytoscapePlugins();

  cy = cytoscape({
    container,
    elements: [],
    minZoom: 0.25,
    maxZoom: 2.5,
    pixelRatio: 1,
    boxSelectionEnabled: false,
    style: [...NODE_STYLES, ...EDGE_STYLES],
    layout: {
      name: (window.cytoscapeCoseBilkent ? 'cose-bilkent' : 'breadthfirst'),
      quality: 'default',
      animate: false,
      nodeRepulsion: 80000,
      idealEdgeLength: 220,
      gravity: 0.25,
      numIter: 1200,
      tile: true
    }
  });

  if (typeof cy.minimap === 'function') {
    try { cy.minimap({}); } catch {}
  }

  cy.on('select', 'node,edge', (e) => {
    const d = e.target.data();
    renderDetails(d);
    const sel = getFindingsForElement(d);
    console.log('[ui] selection findings:', d.id, d.type, d.severity, '->', Array.isArray(sel) ? sel.length : 0);
    renderFindings(sel && sel.length ? sel : (window.lastFindings || []));
  });

  cy.on('unselect', () => {
    document.getElementById('details').innerHTML = '<div class="muted">Select a node or edge.</div>';
    renderFindings(window.lastFindings || []);
  });

  const resetBtn = document.getElementById('btn-reset');
  if (resetBtn) resetBtn.addEventListener('click', () => cy.fit(null, 60));

  const rect = cy.container().getBoundingClientRect();
  console.log('[ui] cy container rect:', rect);
}

/* ---------------------
   Enumerate handler
---------------------- */
async function handleEnumerateClick() {
  console.log('[ui] Enumerate clicked');
  const ak = (document.getElementById('ak')?.value || '').trim();
  const sk = (document.getElementById('sk')?.value || '').trim();
  const btn = document.getElementById('btn-enumerate');
  if (!ak || !sk) { renderWarnings(['Please provide both Access Key ID and Secret Access Key.']); return; }

  const rid = newRid();
  showProgress();
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => pollProgress(rid), 500);

  btn.loading = true;
  try {
    const { ok, status, data } = await postEnumerate(rid);
    if (!ok) { renderWarnings([data?.error || `Request failed with ${status}`]); return; }

    let elements = data?.elements || [];
    console.log('[ui] elements count:', elements.length);
    window.lastElements = elements;

    // Findings
    window.lastFindings  = Array.isArray(data?.findings) ? data.findings : [];
    window.findingsById  = data?.findings_by_id || indexFindings(window.lastFindings);
    console.log('[ui] findings total:', window.lastFindings.length,
                'indexed ids:', Object.keys(window.findingsById || {}).slice(0, 5));

    // Show all findings by default
    renderFindings(window.lastFindings);

    // Graph
    elements = sanitizeElements(elements);
    elements = markContainers(elements);
    elements = injectIcons(elements);

    cy.elements().remove();
    cy.add(elements);
    cy.resize();

    const layout = cy.layout({
      name: (window.cytoscapeCoseBilkent ? 'cose-bilkent' : 'breadthfirst'),
      quality: 'default',
      animate: false,
      nodeRepulsion: 80000,
      idealEdgeLength: 220,
      gravity: 0.25,
      numIter: 1200,
      tile: true
    });
    layout.run();
    layout.on('layoutstop', () => { cy.fit(null, 60); });
    setTimeout(() => { cy.fit(null, 60); }, 120);

    console.log('[ui] nodes:', cy.nodes().size(), 'edges:', cy.edges().size(),
                'rect:', cy.container().getBoundingClientRect());
    renderWarnings(data.warnings || []);
  } catch (e) {
    renderWarnings([String(e)]);
  } finally {
    btn.loading = false;
    setTimeout(() => pollProgress(rid), 200);
  }
}

/* ---------------------
   Bind & boot
---------------------- */
function bindUI() {
  console.log('[ui] bindUI');
  const btn = document.getElementById('btn-enumerate');
  if (!btn) { console.error('[ui] enumerate button not found'); return; }
  Promise.all([
    customElements.whenDefined('sl-button'),
    customElements.whenDefined('sl-input'),
    customElements.whenDefined('sl-progress-bar'),
    customElements.whenDefined('sl-alert')   // ensure alert is defined before we use it
  ]).then(() => {
    console.log('[ui] custom elements ready; binding click handlers');
    btn.addEventListener('click', handleEnumerateClick);
    btn.addEventListener('sl-click', handleEnumerateClick);
    ['ak', 'sk'].forEach(id => {
      const el = document.getElementById(id);
      el && el.addEventListener('keydown', e => { if (e.key === 'Enter') handleEnumerateClick(); });
    });
  }).catch(() => {
    btn.addEventListener('click', handleEnumerateClick);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('[ui] DOMContentLoaded');
  bindUI();
  try { initCySafe(); } catch (e) { renderWarnings([String(e)]); }
  legend();
  ensureFindingsContainer();
});

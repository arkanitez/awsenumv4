/* app/ui/app.js */
console.log('[ui] script loaded');

let cy;
let progressTimer = null;
let progressBackoffMs = 500; // backoff for the poller

/* ---------------------
   Warnings helper
---------------------- */
function pushWarning(msg) {
  const w = document.getElementById('warnings');
  if (!w) return;
  const a = document.createElement('sl-alert');
  a.variant = 'warning';
  a.closable = true;
  a.open = true;
  a.innerText = String(msg);
  w.appendChild(a);
  const det = [...document.querySelectorAll(
    '#details sl-alert[variant="warning"], #details sl-alert[variant="danger"]'
  )];
  if (det.length > 12) det.slice(0, det.length - 12).forEach(x => x.remove());
}

/* ---------------------
   Legend (simple)
---------------------- */
function legend() {
  const el = document.getElementById('legend');
  if (!el) return;
  el.innerHTML = `
    <div style="display:flex; gap:14px; flex-wrap:wrap; align-items:center; font-size:12px">
      <span><span style="display:inline-block;width:12px;height:12px;border:3px solid #ef4444;border-radius:3px;margin-right:6px;"></span>High</span>
      <span><span style="display:inline-block;width:12px;height:12px;border:2px solid #f59e0b;border-radius:3px;margin-right:6px;"></span>Medium</span>
      <span><span style="display:inline-block;width:12px;height:12px;border:1.5px solid #facc15;border-radius:3px;margin-right:6px;"></span>Low</span>
      <span><span style="display:inline-block;width:18px;height:2px;background:#f97316;margin-right:6px;"></span>Network</span>
      <span><span style="display:inline-block;width:18px;height:2px;background:#2563eb;margin-right:6px;"></span>Resource</span>
      <span><span style="display:inline-block;width:18px;height:2px;background:#0ea5e9;margin-right:6px;border-bottom:1px dotted #0ea5e9;"></span>Data</span>
    </div>
  `;
}

/* ---------------------
   Warnings panel render
---------------------- */
function renderWarnings(list) {
  if (!Array.isArray(list) || list.length === 0) return;
  list.forEach(pushWarning);
}

/* ---------------------
   Severity → Shoelace variant
---------------------- */
function slVariantForSeverity(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'HIGH') return 'danger';
  if (s === 'MEDIUM') return 'warning';
  return 'neutral';
}

/* ---------------------
   Misc helpers
---------------------- */
function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}
function idLastSegment(id) {
  const s = String(id || '');
  const t = s.split(':').pop();
  return t.includes('/') ? t.split('/').pop() : t;
}
function lambdaNameFromArn(arn) {
  const s = String(arn || '');
  const i = s.indexOf(':function:');
  return i >= 0 ? s.substring(i + ':function:'.length) : '';
}
function ensureArray(a) { return Array.isArray(a) ? a : []; }

/* ---------------------
   Icons (fallbacks if missing)
---------------------- */
const ICONS = {
  vpc: '/ui/icons/vpc.svg',
  subnet: '/ui/icons/subnet.svg',
  instance: '/ui/icons/ec2-instance.svg',
  ec2: '/ui/icons/ec2-instance.svg',
  load_balancer: '/ui/icons/alb.svg',
  nlb: '/ui/icons/alb.svg',
  apigw: '/ui/icons/api-gateway.svg',
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
  api_gw_v2_route: '/ui/icons/api-gateway-route.svg',
  eni: '/ui/icons/eni.svg',
  nat_gateway: '/ui/icons/nat-gateway.svg',
  route_table: '/ui/icons/route-table.svg',
  security_group: '/ui/icons/security-group.svg',
  target_group: '/ui/icons/target-group.svg'
};

/* ---------------------
   Containers (pale fills)
---------------------- */
const CONTAINER_COLOR = {
  vpc:          { fill: 'rgba(223, 252, 243, 0.06)',  border: '#10b981' }, // emerald
  subnet:       { fill: 'rgba(228, 238, 254, 0.06)',  border: '#3b82f6' }, // blue
  eks_cluster:  { fill: 'rgba(245, 158, 11, 0.06)',  border: '#f59e0b' }, // amber
  ecs_cluster:  { fill: 'rgba(147, 51, 234, 0.06)',  border: '#9333ea' }, // purple
  rds_cluster:  { fill: 'rgba(99, 102, 241, 0.06)',  border: '#6366f1' }  // indigo
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
  { selector: 'node[severity = "medium"], node[severity = "MEDIUM"]', style: {
      'border-color': '#f59e0b',
      'border-width': 2
  }},
  { selector: 'node[severity = "low"], node[severity = "LOW"]', style: {
      'border-color': '#facc15',
      'border-width': 1.5
  }},
  { selector: 'node.faded', style: { 'opacity': 0.18 } },
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
  { selector: 'edge[severity = "medium"], edge[severity = "MEDIUM"]', style: {
      'line-color': '#f59e0b',
      'target-arrow-color': '#f59e0b',
      'width': 2
  }},
  { selector: 'edge[severity = "low"], edge[severity = "LOW"]', style: {
      'line-color': '#facc15',
      'target-arrow-color': '#facc15',
      'width': 1.5
  }},
  { selector: 'edge.faded', style: { 'opacity': 0.18 } },
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

  const details = document.getElementById('details');
  const parent = details ? details.parentElement : document.body;

  const wrap = document.createElement('div');
  wrap.id = 'findings';
  wrap.className = 'findings';
  wrap.style.padding = '8px 10px';
  wrap.style.maxHeight = '40vh';
  wrap.style.overflow = 'auto';
  wrap.style.borderTop = '1px solid #eee';
  parent.appendChild(wrap);
  return wrap;
}

/* ---------------------
   Links & details
---------------------- */
function buildQuickLinks(data) {
  const links = [];
  const type = String(data?.type || '');
  const region = String(data?.region || '');
  const details = data?.details || {};
  const id = String(data?.id || '');

  // S3 bucket
  if (type === 's3_bucket') {
    const bucket = details.name || details.bucket || idLastSegment(id);
    if (bucket) {
      links.push({
        title: 'Open in AWS Console',
        href: `https://s3.console.aws.amazon.com/s3/buckets/${encodeURIComponent(bucket)}?region=${encodeURIComponent(region)}&tab=properties`
      });
      const akv = (document.getElementById('ak')?.value || '').trim();
      const skv = (document.getElementById('sk')?.value || '').trim();
      const credQS = akv && skv ? `&ak=${encodeURIComponent(akv)}&sk=${encodeURIComponent(skv)}` : '';
      links.push({
        title: 'Download S3 bucket configuration (JSON)',
        href: `/download/s3-config?region=${encodeURIComponent(region)}&bucket=${encodeURIComponent(bucket)}${credQS}`
      });
    }
  }

  // Lambda
  if (type === 'lambda') {
    const arn = details.arn || idLastSegment(id);
    const name = details.name || lambdaNameFromArn(arn) || data.label || '';
    const link = `https://${region}.console.aws.amazon.com/lambda/home?region=${encodeURIComponent(region)}#/functions/${encodeURIComponent(name)}?tab=code`;
    links.push({ title: 'Open in AWS Console', href: link });
  }

  // CloudFront
  if (type === 'cloudfront') {
    const dist = idLastSegment(id);
    links.push({
      title: 'Open in AWS Console',
      href: `https://us-east-1.console.aws.amazon.com/cloudfront/v4/home?region=us-east-1#/distributions/${encodeURIComponent(dist)}`
    });
  }

  // CloudWatch Log Group
  if (type === 'cloudwatch_log_group') {
    const name = details.logGroupName || idLastSegment(id);
    links.push({
      title: 'Open log group',
      href: `https://${region}.console.aws.amazon.com/cloudwatch/home?region=${encodeURIComponent(region)}#logsV2:log-groups/log-group/${encodeURIComponent(name)}`
    });
  }

  return links;
}

function renderFindings(findings) {
  const el = ensureFindingsContainer();
  const arr = Array.isArray(findings) ? findings : [];
  el.innerHTML = '';
  if (arr.length === 0) {
    const t = document.createElement('div');
    t.className = 'muted';
    t.innerText = 'No findings.';
    el.appendChild(t);
    return;
  }
  for (const f of arr) {
    const a = document.createElement('sl-alert');
    a.variant = slVariantForSeverity(f.severity);
    a.closable = true;
    a.open = true;
    a.innerText = `[${f.severity || 'INFO'}] ${f.title || ''}${f.detail ? ': ' + f.detail : ''}`;
    el.appendChild(a);
  }
}

function renderDetails(data) {
  const el = document.getElementById('details');
  if (!el) return;

  const existing = (data?.details && Array.isArray(data.details.links)) ? data.details.links : [];
  const computed = buildQuickLinks(data);

  const byHref = new Map();
  for (const l of [...existing, ...computed]) {
    if (!l || !l.href) continue;
    const key = String(l.href);
    if (!byHref.has(key)) byHref.set(key, { title: l.title || 'link', href: l.href });
  }
  const links = [...byHref.values()];

  let html = '';
  if (links.length) {
    html += '<div style="margin-bottom:8px"><strong>Downloads & Quick Links</strong><ul style="margin:6px 0 10px 18px">';
    for (const l of links) {
      html += `<li><a href="${escapeHtml(l.href)}" target="_blank" rel="noreferrer">${escapeHtml(l.title)}</a></li>`;
    }
    html += '</ul></div>';
  }

  html += `<pre style="max-height:38vh;overflow:auto;border:1px solid #eee;padding:10px;background:#fafafa;border-radius:6px">${escapeHtml(JSON.stringify(data?.details || {}, null, 2))}</pre>`;
  el.innerHTML = html;
}

/* ---------------------
   Findings index
---------------------- */
function indexFindings(list) {
  const byId = {};
  for (const f of Array.isArray(list) ? list : []) {
    const id = String(f.id || '');
    (byId[id] ||= []).push(f);
  }
  return byId;
}
function getFindingsForElement(data) {
  const id = String(data?.id || '');
  return (window.findingsById && window.findingsById[id]) || [];
}

/* ---------------------
   Containers / icons / sanitization
---------------------- */
function markContainers(elements) {
  const out = [];
  for (const el of elements) {
    if (el.group !== 'nodes') { out.push(el); continue; }
    const d = el.data || {};
    if (!d.type) { out.push(el); continue; }

    if (['vpc','subnet','eks_cluster','ecs_cluster','rds_cluster'].includes(d.type)) {
      el.classes = (el.classes || '') + ' container container-' + d.type;
    }
    out.push(el);
  }
  return out;
}
function injectIcons(elements) {
  for (const el of elements) {
    if (el.group !== 'nodes') continue;
    const d = el.data || {};
    if (d.icon) continue;
    const icon = ICONS[d.type];
    if (icon) {
      d.icon = icon;
      el.classes = (el.classes || '') + ' has-icon';
    }
  }
  return elements;
}
function sanitizeElements(elements) {
  const arr = Array.isArray(elements)
    ? elements
    : (elements && Array.isArray(elements.nodes) && Array.isArray(elements.edges))
      ? [...elements.nodes, ...elements.edges]
      : [];

  const ok = [];

  for (const el of arr) {
    if (!el || !el.data) continue;

    const d = el.data;
    // Infer group if missing
    const isEdge = !!(d.source && d.target);
    const group = el.group || (isEdge ? 'edges' : 'nodes');

    if (group === 'edges') {
      // Require a valid edge
      if (!d.source || !d.target) continue;
      el.group = 'edges';
      if (d.label == null) d.label = '';
    } else {
      // Require a valid node
      if (!d.id) continue;
      el.group = 'nodes';
      if (d.label == null) d.label = d.name || d.id;
    }

    // Normalize classes if an array was provided
    if (Array.isArray(el.classes)) el.classes = el.classes.join(' ');

    ok.push(el);
  }

  return ok;
}

/* ---------------------
   Cluster-aware layout helpers (no external plugins)
---------------------- */
function _runCose(eles, opts = {}) {
  const lay = eles.layout({
    name: 'cose',
    animate: false,
    fit: false,
    padding: 20,
    idealEdgeLength: (opts && opts.idealEdgeLength) || 110,
    nodeRepulsion: (opts && opts.nodeRepulsion) || 400000,
    edgeElasticity: (opts && opts.edgeElasticity) || 100,
    nestingFactor: (opts && opts.nestingFactor) || 0.8,
    gravity: (opts && opts.gravity) || 1,
    componentSpacing: (opts && opts.componentSpacing) || 70,
    numIter: (opts && opts.numIter) || 1500,
    initialTemp: 200,
    coolingFactor: 0.95,
    minTemp: 1.0,
    randomize: true
  });
  lay.run();
}

function _bbCenter(bb) {
  return { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2, w: bb.w, h: bb.h };
}

function _moveBy(collection, dx, dy) {
  collection.positions(n => {
    const p = n.position();
    return { x: p.x + dx, y: p.y + dy };
  });
}

function _packGrid(rects, spacing) {
  if (!rects.length) return [];
  const maxW = Math.max.apply(null, rects.map(r => r.bb.w || 1));
  const maxH = Math.max.apply(null, rects.map(r => r.bb.h || 1));
  const stepX = maxW + spacing;
  const stepY = maxH + spacing;
  const cols = Math.max(1, Math.ceil(Math.sqrt(rects.length)));
  const placements = [];
  for (let i = 0; i < rects.length; i++) {
    const r = Math.floor(i / cols);
    const c = i % cols;
    placements.push({ i, x: c * stepX, y: r * stepY });
  }
  return placements;
}

function _clusterParents(cy) {
  const parents = cy.nodes('node:parent');
  const vpcs = parents.filter('[type = "vpc"]');
  const others = parents.difference(vpcs);
  return vpcs.union(others);
}

function _topLevelNodes(cy) {
  return cy.nodes().filter(n => n.ancestors().length === 0 && !n.isParent());
}

function applyReadableLayout(cy, opts = {}) {
  const spacing = (opts && opts.spacing) || 320;
  const coseOpts = (opts && opts.cose) || {};
  cy.startBatch();

  cy.style()
    .selector('node')
    .style({ 'text-wrap': 'wrap', 'text-max-width': 160 })
    .selector('node:parent')
    .style({ 'padding': 18, 'background-opacity': 0.04, 'text-valign': 'top', 'text-halign': 'center' })
    .update();

  const parents = _clusterParents(cy);
  const clusters = [];
  parents.forEach(p => {
    const group = p.union(p.descendants());
    if (group.length > 0) {
      _runCose(group, coseOpts);
      const bb = group.boundingBox({ includeLabels: true, includeOverlays: false });
      clusters.push({ id: p.id(), nodes: group, bb: _bbCenter(bb) });
    }
  });

  const top = _topLevelNodes(cy);
  if (top.length > 0) {
    const lay = top.layout({
      name: 'concentric',
      animate: false,
      fit: false,
      concentric: n => (n.data('severity') === 'high' ? 3 : Math.max(1, n.degree(false))),
      levelWidth: () => 1,
      minNodeSpacing: 60,
      startAngle: (3 * Math.PI) / 2,
      sweep: 2 * Math.PI,
      padding: 40
    });
    lay.run();
  }

  if (clusters.length > 0) {
    const placements = _packGrid(clusters, spacing);
    placements.forEach(pl => {
      const c = clusters[pl.i];
      const cur = c.bb;
      const dx = pl.x - cur.x;
      const dy = pl.y - cur.y;
      _moveBy(c.nodes, dx, dy);
    });
  }

  cy.endBatch();
  cy.fit(cy.elements(), 60);
}

/* ---------------------
   Progress bar (visible text + robust poller)
---------------------- */
function ensureProgressBar() {
  let wrap = document.getElementById('progress-wrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'progress-wrap';
    wrap.style.position = 'fixed';
    wrap.style.left = '0';
    wrap.style.right = '0';
    wrap.style.top = '0';
    wrap.style.padding = '10px 16px 12px 16px';
    wrap.style.pointerEvents = 'none';
    wrap.style.zIndex = '9999';

    const inner = document.createElement('div');
    inner.id = 'progress-inner';
    inner.style.maxWidth = '960px';
    inner.style.margin = '0 auto';
    inner.style.pointerEvents = 'auto';
    inner.style.background = 'rgba(255,255,255,0.94)';
    inner.style.border = '1px solid #e5e7eb';
    inner.style.borderRadius = '10px';
    inner.style.boxShadow = '0 6px 18px rgba(0,0,0,0.08)';
    inner.style.padding = '10px 12px';

    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.alignItems = 'center';
    row.style.gap = '10px';

    const bar = document.createElement('sl-progress-bar');
    bar.id = 'progress-bar';
    bar.style.width = '100%';
    bar.style.setProperty('--height', '10px');
    bar.value = 0;

    const text = document.createElement('div');
    text.id = 'progress-text';
    text.style.minWidth = '260px';
    text.style.fontSize = '12px';
    text.style.color = '#334155';

    row.appendChild(bar);
    row.appendChild(text);
    inner.appendChild(row);
    wrap.appendChild(inner);
    document.body.appendChild(wrap);
  }
  return wrap;
}

function showProgress(initialLabel = 'Enumerating…') {
  const wrap = ensureProgressBar();
  wrap.style.display = 'block';
  const bar = document.getElementById('progress-bar');
  const text = document.getElementById('progress-text');
  if (bar) {
    bar.setAttribute('indeterminate', '');
    bar.value = 0;
  }
  if (text) text.textContent = initialLabel;
}
function hideProgress() {
  const wrap = document.getElementById('progress-wrap');
  if (wrap) wrap.style.display = 'none';
}
function _coercePercent(v) {
  if (v === null || v === undefined) return null;
  const n = typeof v === 'string' ? parseFloat(v) : v;
  if (typeof n !== 'number' || isNaN(n)) return null;
  if (n <= 1) return Math.max(0, Math.min(1, n)) * 100; // accept 0..1
  return Math.max(0, Math.min(100, n));                  // accept 0..100
}
function _labelFrom(data) {
  return (
    (data && (data.label || data.stage)) ||
    (data && data.service && data.region && `${data.region} · ${data.service}`) ||
    (data && data.service) ||
    ''
  ).toString();
}
function _percentFrom(data) {
  // accept value/pct/progress, or derive from current/total, or from step/steps etc.
  const direct = _coercePercent(data && (data.value ?? data.percent ?? data.pct ?? data.progress));
  if (direct !== null) return direct;
  const cur = data && (data.current ?? data.step ?? data.i);
  const tot = data && (data.total ?? data.steps ?? data.n);
  if (typeof cur === 'number' && typeof tot === 'number' && tot > 0) {
    return Math.max(0, Math.min(100, (cur / tot) * 100));
  }
  return null;
}
async function pollProgress(rid) {
  const bar = document.getElementById('progress-bar');
  const text = document.getElementById('progress-text');
  if (!bar || !text) return;

  try {
    const res = await fetch(`/progress?rid=${encodeURIComponent(rid)}`, { cache: 'no-store' });
    const data = await res.json().catch(() => ({}));

    const pct = _percentFrom(data);
    const label = _labelFrom(data);

    if (pct !== null) {
      bar.removeAttribute('indeterminate');
      bar.value = pct;
      text.textContent = label ? `${label} (${pct.toFixed(0)}%)` : `${pct.toFixed(0)}%`;
    } else {
      bar.setAttribute('indeterminate', '');
      if (label) text.textContent = label;
    }

    progressBackoffMs = 500;

    if (data && data.done === true) {
      clearInterval(progressTimer);
      progressTimer = null;
      setTimeout(hideProgress, 600);
    }
  } catch {
    bar.setAttribute('indeterminate', '');
    text.textContent = 'Working…';
    progressBackoffMs = Math.min(progressBackoffMs * 2, 5000);
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = setInterval(() => pollProgress(rid), progressBackoffMs);
    }
  }
}

/* ---------------------
   Enumerate POST
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
    renderFindings(sel);
  });

  cy.on('unselect', () => {
    document.getElementById('details').innerHTML = '<div class="muted">Select a node or edge.</div>';
    renderFindings(window.lastFindings || []);
  });

  // Focus mode
  cy.on('tap', 'node', (evt) => {
    if (evt.originalEvent && (evt.originalEvent.ctrlKey || evt.originalEvent.metaKey)) return;
    const n = evt.target;
    const hood = n.closedNeighborhood();
    cy.elements().addClass('faded');
    hood.removeClass('faded');
    n.removeClass('faded');
  });
  cy.on('tap', (evt) => {
    if (evt.target === cy) cy.elements().removeClass('faded');
  });

  const resetBtn = document.getElementById('btn-reset');
  if (resetBtn) resetBtn.addEventListener('click', () => cy.fit(null, 60));
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

  const rid = ('rid_' + Math.random().toString(36).slice(2));
  window.lastRid = rid;
  showProgress('Enumerating…');

  progressBackoffMs = 500;
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => pollProgress(rid), progressBackoffMs);

  btn.loading = true;
  try {
    const { ok, status, data } = await postEnumerate(rid);
    if (!ok) { renderWarnings([data?.error || `Request failed with ${status}`]); return; }

    // Support either a flat array OR { nodes: [...], edges: [...] }
    if (!Array.isArray(elements) && elements && Array.isArray(elements.nodes) && Array.isArray(elements.edges)) {
      elements = [...elements.nodes, ...elements.edges];
    }
    
    console.log('[ui] elements count:', Array.isArray(elements) ? elements.length : 'n/a');
    window.lastElements = elements;

    window.lastFindings  = Array.isArray(data?.findings) ? data.findings : [];
    window.findingsById  = data?.findings_by_id || indexFindings(window.lastFindings);
    console.log('[ui] findings total:', window.lastFindings.length,
                'indexed ids:', Object.keys(window.findingsById || {}).slice(0, 5));

    renderFindings(window.lastFindings);

    elements = sanitizeElements(elements);
    elements = markContainers(elements);
    elements = injectIcons(elements);

    cy.elements().remove();
    cy.add(elements);
    cy.resize();

    applyReadableLayout(cy, {
      spacing: 340,
      cose: { idealEdgeLength: 110, nodeRepulsion: 420000, componentSpacing: 70 }
    });

    console.log('[ui] nodes:', cy.nodes().size(), 'edges:', cy.edges().size());
    renderWarnings(data.warnings || []);
  } catch (e) {
    renderWarnings([String(e)]);
  } finally {
    btn.loading = false;
    clearInterval(progressTimer); progressTimer = null;
    setTimeout(hideProgress, 600);
  }
}

/* ---------------------
   Bind UI
---------------------- */
function bindUI() {
  const btn = document.getElementById('btn-enumerate');
  if (!btn) return;

  Promise.resolve().then(() => {
    if ('sl-click' in (btn.__proto__ || {})) {
      btn.addEventListener('sl-click', handleEnumerateClick);
    }
    btn.addEventListener('click', handleEnumerateClick);

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

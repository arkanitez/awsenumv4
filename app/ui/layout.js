// app/ui/layout.js
// Cluster-aware layout: run COSE inside each compound, then pack clusters on a grid.
// Also handles top-level nodes separately so the graph doesn't collapse into one blob.

(function () {
  function runCose(eles, opts = {}) {
    const lay = eles.layout({
      name: "cose",
      animate: false,
      fit: false,
      padding: 20,
      idealEdgeLength: opts.idealEdgeLength ?? 110,
      nodeRepulsion: opts.nodeRepulsion ?? 400000,
      edgeElasticity: opts.edgeElasticity ?? 100,
      nestingFactor: opts.nestingFactor ?? 0.8,
      gravity: opts.gravity ?? 1,
      componentSpacing: opts.componentSpacing ?? 70,
      numIter: opts.numIter ?? 1500,
      initialTemp: 200,
      coolingFactor: 0.95,
      minTemp: 1.0,
      randomize: true
    });
    lay.run();
  }

  function bbCenter(bb) {
    return { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2, w: bb.w, h: bb.h };
  }

  function moveBy(collection, dx, dy) {
    collection.positions((n) => {
      const p = n.position();
      return { x: p.x + dx, y: p.y + dy };
    });
  }

  function packGrid(rects, spacing) {
    // rects: [{ id, bb:{x1,x2,y1,y2,w,h}, nodes:cy collection }]
    const maxW = Math.max(1, ...rects.map((r) => r.bb.w));
    const maxH = Math.max(1, ...rects.map((r) => r.bb.h));
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

  function clusterParents(cy) {
    // Treat any compound node as a cluster parent (e.g., VPCs, subnets if you use them as parents).
    // Prefer VPCs first, then other parents.
    const parents = cy.nodes("node:parent");
    const vpcs = parents.filter('[type = "vpc"]');
    const others = parents.difference(vpcs);
    // Keep deterministic order for packing
    return vpcs.union(others).sort((a, b) => (a.id() < b.id() ? -1 : 1));
  }

  function topLevelNodes(cy) {
    // Nodes that have no ancestors (not inside any compound) and are not cluster parents themselves.
    return cy.nodes().filter((n) => n.ancestors().length === 0 && !n.isParent());
  }

  function layoutTopLevel(cy, opts = {}) {
    const top = topLevelNodes(cy);
    if (top.nonempty()) {
      // Spread top-level stuff in a circle to one side
      const lay = top.layout({
        name: "concentric",
        animate: false,
        fit: false,
        concentric: (n) => (n.data("severity") === "high" ? 3 : n.degree()),
        levelWidth: () => 1,
        minNodeSpacing: opts.minNodeSpacing ?? 60,
        startAngle: (3 * Math.PI) / 2,
        sweep: 2 * Math.PI,
        padding: 40
      });
      lay.run();
    }
  }

  function applyReadableLayout(cy, opts = {}) {
    const spacing = opts.spacing ?? 320; // space between clusters
    const coseOpts = opts.cose ?? {};
    cy.startBatch();

    // 0) Wrap labels and pad parents so text doesn't collide
    cy.style()
      .selector("node")
      .style({
        "text-wrap": "wrap",
        "text-max-width": "140px"
      })
      .selector("node:parent")
      .style({
        "padding": "18px",
        "background-opacity": 0.04,
        "text-valign": "top",
        "text-halign": "center"
      })
      .update();

    // 1) Layout each cluster parent (e.g., VPC) independently with COSE
    const parents = clusterParents(cy);
    const clusters = [];
    parents.forEach((p) => {
      const group = p.union(p.descendants());
      if (group.nonempty()) {
        runCose(group, coseOpts);
        const bb = group.boundingBox({ includeLabels: true, includeOverlays: false });
        clusters.push({ id: p.id(), nodes: group, bb: bbCenter(bb) });
      }
    });

    // 2) Layout everything not in a cluster (top-level/global) before packing
    layoutTopLevel(cy, { minNodeSpacing: 70 });

    // 3) Pack clusters on a grid and move each cluster to its tile center
    if (clusters.length > 0) {
      const placements = packGrid(clusters, spacing);
      placements.forEach((pl) => {
        const c = clusters[pl.i];
        const cur = c.bb;
        const dx = pl.x - cur.x;
        const dy = pl.y - cur.y;
        moveBy(c.nodes, dx, dy);
      });
    }

    cy.endBatch();
    cy.fit(cy.elements(), 40);
  }

  // expose
  window.applyReadableLayout = applyReadableLayout;
})();

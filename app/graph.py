from __future__ import annotations

from typing import Any, Dict, List, Optional
import threading


def _clean_none(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of d without None-valued keys."""
    return {k: v for k, v in d.items() if v is not None}


class Graph:
    """Thread-safe elements store for Cytoscape-compatible graphs."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add_node(
        self,
        id_: str,
        label: str,
        type_: str,
        region: str,
        details: Optional[Dict[str, Any]] = None,
        parent: Optional[str] = None,
        icon: Optional[str] = None,
    ) -> None:
        """Add or update a node.

        - Ensures `group: "nodes"` so Cytoscape treats it as a node.
        - Merges details if node already exists.
        - Only sets `parent` if provided (avoids null).
        - Adds `icon` only if it's a non-empty string (frontend will also map icons).
        """
        if not id_:
            return

        with self._lock:
            if id_ in self._nodes:
                node = self._nodes[id_]
                # Merge details and set parent if previously unset
                if details:
                    node["data"].setdefault("details", {}).update(details)
                if parent and not node["data"].get("parent"):
                    node["data"]["parent"] = parent
                # Keep label/type/region fresh if callers pass updated values
                if label:
                    node["data"]["label"] = label
                if type_:
                    node["data"]["type"] = type_
                if region:
                    node["data"]["region"] = region
                if icon and isinstance(icon, str) and icon.strip():
                    node["data"]["icon"] = icon
                return

            data = {
                "id": id_,
                "label": label or id_,
                "type": type_,
                "region": region,
                "details": details or {},
                "parent": parent,
            }
            if icon and isinstance(icon, str) and icon.strip():
                data["icon"] = icon

            clean = _clean_none(data)

            self._nodes[id_] = {
                "group": "nodes",
                "data": clean,
                # classes are optional but useful for styling/filtering later
                "classes": f"aws-node {type_}".strip(),
            }

    def add_edge(
        self,
        id_: str,
        src: str,
        tgt: str,
        label: str,
        type_: str,
        category: str,
        derived: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an edge.

        - Ensures `group: "edges"` so Cytoscape treats it as an edge.
        - Stores `derived` as a string ("true"/"false") to match style selector edge[derived = "true"].
        """
        if not id_ or not src or not tgt:
            return

        with self._lock:
            if id_ in self._edges:
                # Merge details if re-added with extra info
                if details:
                    self._edges[id_]["data"].setdefault("details", {}).update(details)
                return

            data = _clean_none(
                {
                    "id": id_,
                    "source": src,
                    "target": tgt,
                    "label": label,
                    "type": type_,
                    "category": category,
                    "derived": "true" if derived else "false",
                    "details": details or {},
                }
            )
            self._edges[id_] = {
                "group": "edges",
                "data": data,
                # include both category and type for flexible styling (e.g. resource-edge, network-edge)
                "classes": " ".join(
                    filter(
                        None,
                        [
                            f"{category}-edge" if category else None,
                            f"{type_}-edge" if type_ else None,
                        ],
                    )
                ),
            }

    def elements(self) -> List[Dict[str, Any]]:
        """Return a stable list of nodes then edges (safe to iterate multiple times).

        Critically, this filters out edges whose source/target nodes do not exist.
        Cytoscape will otherwise throw and refuse to load the entire batch.
        """
        with self._lock:
            nodes_list = list(self._nodes.values())
            node_ids = set(self._nodes.keys())

            valid_edges: List[Dict[str, Any]] = []
            for edge in self._edges.values():
                data = edge.get("data") or {}
                src = data.get("source")
                tgt = data.get("target")
                if src in node_ids and tgt in node_ids:
                    valid_edges.append(edge)
                # else: drop silently; frontend also warns when it sanitizes

            # Return nodes first so compound parents (if any) exist before children
            return nodes_list + valid_edges

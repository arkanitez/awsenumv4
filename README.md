# AWSenumv4

A minimal, modern UI to **enumerate your AWS account** and visualize resources as an interactive graph. Designed for quick onboarding: **two inputs** (Access Key ID & Secret Access Key) and **one button** (Enumerate). Default region is `ap-southeast-1`.

> If you’re new to AWS or graph tools: think of this app like **Google Maps for your cloud**. It finds your services (EC2, VPCs, subnets, Lambdas, etc.), draws them as nodes and lines, and lets you click around to see details.

---

## What it does (in plain English)

* **Scans your AWS account** using your access keys (read‑only recommended).
* **Builds an interactive map** of your cloud: services are circles (nodes) and their relationships are lines (edges).
* **Lets you explore**: zoom, pan, and click any item to see its details in the side panel.
* **Helps spot issues**: isolated nodes, unexpected links, or missing relationships become visually obvious.

> Tip: Use a **read-only** IAM policy when testing (e.g., AWS’s `ReadOnlyAccess`).

---

## Quick start

### 1) Prerequisites

* **Python 3.10+** (recommended)
* **pip**
* An AWS IAM user with **read‑only** permissions to the services you want to enumerate

### 2) Install & run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS:
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

---

## How to use it

1. Open the web app (default: `http://127.0.0.1:8000`).
2. Enter your **Access Key ID** and **Secret Access Key**.
3. Click **Enumerate**.
4. Watch the **progress bar** (the bar appears while enumeration runs and hides when done).
5. Explore the graph:

   * **Scroll** to zoom, **drag** to pan.
   * **Click a node** to open a details panel (IDs, ARNs, and links when available).
   * **Use the layout** controls to tidy up the view.

> Large accounts can take longer. Start with a few services enabled on your IAM user if you want a fast demo.

---

## What gets enumerated

The exact set can grow over time, but typically includes:

* **Networking**: VPCs, subnets, route tables, Internet/NAT gateways, VPC endpoints
* **Compute**: EC2 instances, Auto Scaling groups, EKS clusters & nodes, Lambda functions
* **Storage & Data**: S3 buckets, DynamoDB tables
* **Identity & Access (select)**: relevant relationships to show how things connect

Each item appears as a node. **Edges** show relationships (e.g., an EC2 instance in a subnet; a Lambda linked to a VPC or an event source).

> Where applicable, the details panel includes **helpful links** (for example to AWS Console) and, when the feature is available, **download links** to artifacts (e.g., Lambda code) with proper IAM permissions.

---

## Security recommendations

* **Use least privilege.** Prefer an IAM policy limited to the services you want to enumerate.
* **Avoid production credentials** for experimentation.
* **Rotate keys** after demos.
* **Network access**: run locally; if deployed, protect the server behind your usual controls.

Example: start with AWS managed **`ReadOnlyAccess`** and then restrict further as needed.

---

## Project structure (high level)

```
awsenumv4/
├─ app/            # FastAPI backend + frontend assets
├─ tests/          # Test files
├─ requirements.txt
└─ README.md
```

* **Backend**: FastAPI + Uvicorn
* **Frontend**: Modern JS UI; graph rendering with Cytoscape (plus plugins for layouts)

---

## Troubleshooting

**Blank/empty graph**

* Check the browser console (F12) for JS errors (often from a missing layout plugin or invalid elements).
* Ensure Cytoscape plugins are registered **before** initializing Cytoscape.
* Verify that every **edge** references existing `source` and `target` node IDs.

**Progress bar stuck**

* Make sure the backend is streaming or updating progress events to the UI.
* Confirm your credentials have permissions to list the targeted services; otherwise enumeration may stall on timeouts.

**CORS or 404s on plugin files**

* If loading plugins from a CDN, ensure correct URLs and that the plugin is **registered** with `cytoscape.use(...)` before use.

**AWS errors / throttling**

* Reduce concurrency or scope; try a single region first.

---

## Developing

* Create a branch and run the app locally as shown above.
* Preferred stack: **FastAPI**, **Uvicorn**, **Cytoscape**.
* Add new service enumerators in the backend, return nodes/edges with stable IDs, and include lightweight details for the side panel.

### Conventions

* **Node IDs** must be unique and stable.
* **Edge targets** must exist; ignore or drop edges referencing missing nodes.
* Keep payloads small for snappy rendering.

---

## FAQ (plain English)

**Is this safe for my account?**
Use **read‑only** creds. The app only reads metadata to draw your cloud. Avoid write permissions.

**Do I need to set environment variables?**
No—enter keys in the UI. Advanced users can configure environment variables or profiles as they extend the app.

**Can I change the region?**
Yes—use the UI region selector (default is `ap-southeast-1`).

**How do I export the graph?**
Use your browser’s screenshot or add a small export button (contributors welcome!).

---

## Credits

* Built with **FastAPI** (backend) and **Cytoscape** (frontend).
* Thanks to contributors and testers.

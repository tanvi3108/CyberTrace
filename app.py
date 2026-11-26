import os
import sqlite3
from datetime import datetime
import pandas as pd
from flask import Flask, render_template, request, jsonify
from data_generator import generate_dataset
from bfs_engine import build_infrastructure_graph, custom_bfs, custom_dfs, reconstruct_path

app = Flask(__name__)

DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "cybertrace.db")

if not os.path.exists(os.path.join(DATA_DIR, "login_logs.csv")):
    generate_dataset(DATA_DIR)


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_timestamp TEXT NOT NULL,
                start_node TEXT NOT NULL,
                target_node TEXT,
                max_depth INTEGER NOT NULL,
                discovered_count INTEGER NOT NULL,
                exec_time_ms REAL NOT NULL
            )
        """)
        conn.commit()


def log_investigation(start_node, target_node, max_depth, discovered_count, exec_time_ms):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO investigations (run_timestamp, start_node, target_node, max_depth, discovered_count, exec_time_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                start_node,
                target_node or "ALL",
                max_depth,
                discovered_count,
                exec_time_ms
            )
        )
        conn.commit()


def get_investigation_count():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT COUNT(*) FROM investigations")
        return cur.fetchone()[0]


def load_csv_data():
    df_emp = pd.read_csv(os.path.join(DATA_DIR, "employees.csv"))
    df_dev = pd.read_csv(os.path.join(DATA_DIR, "devices.csv"))
    df_logs = pd.read_csv(os.path.join(DATA_DIR, "login_logs.csv"))
    return df_emp, df_dev, df_logs


init_db()


# =========================================================
# 5 SEPARATE WEB PAGES
# =========================================================
@app.route("/")
def page_dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/graph")
def page_graph():
    return render_template("graph.html", active_page="graph")


@app.route("/bfs")
def page_bfs():
    return render_template("bfs.html", active_page="bfs")


@app.route("/results")
def page_results():
    return render_template("results.html", active_page="results")


@app.route("/report")
def page_report():
    return render_template("report.html", active_page="report")


# =========================================================
# REST API ENDPOINTS
# =========================================================
@app.route("/api/overview", methods=["GET"])
def api_overview():
    exclude_gw = request.args.get("exclude_gateway", "true").lower() == "true"
    df_emp, df_dev, df_logs = load_csv_data()
    _, _, nodes, edges, _ = build_infrastructure_graph(
        df_emp, df_dev, df_logs, exclude_shared_gateway=exclude_gw
    )

    suspicious_logs = df_logs[df_logs["login_type"] != "Normal-SSO"].to_dict(orient="records")
    suspicious_users_count = int((df_emp["status"] != "Normal").sum())
    employees = df_emp.to_dict(orient="records")

    return jsonify({
        "metrics": {
            "total_users": len(df_emp),
            "connected_devices": len(df_dev),
            "suspicious_accounts": suspicious_users_count,
            "active_investigations": max(1, get_investigation_count()),
            "recent_events_count": len(suspicious_logs)
        },
        "employees": employees,
        "recent_security_events": suspicious_logs,
        "graph": {
            "nodes": list(nodes.values()),
            "edges": edges
        }
    })


@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    payload = request.json or {}
    start_node = payload.get("start_node", "U001")
    target_node = payload.get("target_node", "")
    max_depth = int(payload.get("max_depth", 8))
    exclude_gw = bool(payload.get("exclude_gateway", True))
    start_time = payload.get("start_time") or None
    end_time = payload.get("end_time") or None

    df_emp, df_dev, df_logs = load_csv_data()
    _, adj, nodes, edges, edge_lookup = build_infrastructure_graph(
        df_emp,
        df_dev,
        df_logs,
        exclude_shared_gateway=exclude_gw,
        start_time=start_time,
        end_time=end_time
    )

    bfs_res = custom_bfs(adj, start_node, max_depth=max_depth)
    dfs_res = custom_dfs(adj, start_node, max_depth=max_depth)

    if not bfs_res:
        return jsonify({"error": f"Entity '{start_node}' not found in filtered graph."}), 404

    discovered_entities = []
    for nid in bfs_res["traversal_order"]:
        node_info = nodes[nid].copy()
        lvl = bfs_res["level"][nid]
        par = bfs_res["parent"][nid]
        chain = reconstruct_path(bfs_res["parent"], nid)

        evidence = "Initial Security Alert (Patient Zero)"
        rel_timestamp = "2026-11-26 09:10"
        if par is not None:
            key = tuple(sorted([par, nid]))
            if key in edge_lookup:
                evidence = edge_lookup[key]["evidence"]
                rel_timestamp = edge_lookup[key]["timestamp"]

        node_info["level"] = lvl
        node_info["parent"] = par
        node_info["chain"] = chain
        node_info["timestamp"] = rel_timestamp
        node_info["evidence"] = evidence
        node_info["classification"] = "Confirmed Compromised" if lvl == 0 else "Potentially Exposed"
        discovered_entities.append(node_info)

    shortest_chain = []
    if target_node and target_node in bfs_res["parent"]:
        shortest_chain = reconstruct_path(bfs_res["parent"], target_node)

    log_investigation(
        start_node=start_node,
        target_node=target_node,
        max_depth=max_depth,
        discovered_count=len(discovered_entities),
        exec_time_ms=bfs_res["execution_time_ms"]
    )

    return jsonify({
        "start_node": start_node,
        "target_node": target_node,
        "max_depth": max_depth,
        "active_investigations": get_investigation_count(),
        "bfs": bfs_res,
        "dfs_comparison": dfs_res,
        "discovered": discovered_entities,
        "shortest_chain": shortest_chain,
        "graph": {
            "nodes": list(nodes.values()),
            "edges": edges
        }
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
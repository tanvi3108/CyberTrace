from collections import deque
import time
import networkx as nx


def build_infrastructure_graph(
    df_emp,
    df_dev,
    df_logs,
    exclude_shared_gateway=True,
    start_time=None,
    end_time=None
):
    """
    Constructs a NetworkX graph and clean adjacency dictionary from CSV DataFrames.
    Supports time-window filtering and shared-gateway noise suppression.
    """
    G = nx.Graph()
    nodes = {}
    edges = []
    edge_lookup = {}

    # 1. Add Employee Nodes
    for _, row in df_emp.iterrows():
        nid = row["user_id"]
        meta = {
            "id": nid,
            "label": f"{nid} ({row['name']})",
            "type": "employee",
            "department": row["department"],
            "status": row["status"]
        }
        G.add_node(nid, **meta)
        nodes[nid] = meta

    # 2. Add Device Nodes
    for _, row in df_dev.iterrows():
        nid = row["device_id"]
        meta = {
            "id": nid,
            "label": f"{nid} [{row['device_type']}]",
            "type": "device",
            "device_type": row["device_type"],
            "owner": row["owner"]
        }
        G.add_node(nid, **meta)
        nodes[nid] = meta

    # 3. Apply Investigation Filters (Shared Wi-Fi Noise & Time Window)
    filtered_logs = df_logs.copy()
    if exclude_shared_gateway:
        filtered_logs = filtered_logs[filtered_logs["is_shared_gateway"] == False]
    if start_time:
        filtered_logs = filtered_logs[filtered_logs["timestamp"] >= start_time]
    if end_time:
        filtered_logs = filtered_logs[filtered_logs["timestamp"] <= end_time]

    # 4. Add IP Nodes & Relationships (User <-> Device and Device <-> IP)
    for _, row in filtered_logs.iterrows():
        u = row["user_id"]
        d = row["device_id"]
        ip = row["ip_address"]
        ts = row["timestamp"]
        ltype = row["login_type"]

        if ip not in nodes:
            ip_meta = {
                "id": ip,
                "label": ip,
                "type": "ip",
                "is_gateway": bool(row["is_shared_gateway"])
            }
            G.add_node(ip, **ip_meta)
            nodes[ip] = ip_meta

        relationships = [
            (u, d, f"{ltype} @ {ts}"),
            (d, ip, f"Routed via {ip} @ {ts}")
        ]

        for src, dst, evidence in relationships:
            G.add_edge(src, dst)
            key = tuple(sorted([src, dst]))
            if key not in edge_lookup:
                edge_obj = {
                    "id": f"{key[0]}__{key[1]}",
                    "source": key[0],
                    "target": key[1],
                    "evidence": evidence,
                    "timestamp": ts,
                    "login_type": ltype
                }
                edge_lookup[key] = edge_obj
                edges.append(edge_obj)

    # Convert NetworkX neighbors into sorted adjacency dictionary for deterministic manual traversal
    adj = {node: sorted(list(G.neighbors(node))) for node in G.nodes()}
    return G, adj, nodes, edges, edge_lookup


def custom_bfs(adj, start_node, max_depth=5):
    """
    Manual Breadth-First Search (FIFO Queue) implementation.
    Tracks visited set, parent pointers, discovery levels, layer groups, and execution time.
    """
    t0 = time.perf_counter()
    if start_node not in adj:
        return {}

    queue = deque([start_node])
    visited = {start_node}
    parent = {start_node: None}
    level = {start_node: 0}
    traversal_order = []
    layers = {}

    while queue:
        current = queue.popleft()
        curr_lvl = level[current]

        traversal_order.append(current)
        layers.setdefault(curr_lvl, []).append(current)

        # Respect analyst's investigation depth cutoff
        if curr_lvl >= max_depth:
            continue

        for neighbour in adj.get(current, []):
            if neighbour not in visited:
                visited.add(neighbour)
                parent[neighbour] = current
                level[neighbour] = curr_lvl + 1
                queue.append(neighbour)

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {
        "visited": list(visited),
        "parent": parent,
        "level": level,
        "layers": layers,
        "traversal_order": traversal_order,
        "execution_time_ms": elapsed_ms
    }


def custom_dfs(adj, start_node, max_depth=5):
    """
    Manual Depth-First Search (LIFO Stack) implementation for experimental viva comparison.
    """
    t0 = time.perf_counter()
    if start_node not in adj:
        return {}

    stack = [(start_node, 0)]
    visited = set()
    traversal_order = []

    while stack:
        current, depth = stack.pop()
        if current not in visited:
            visited.add(current)
            traversal_order.append(current)
            if depth < max_depth:
                for neighbour in reversed(adj.get(current, [])):
                    if neighbour not in visited:
                        stack.append((neighbour, depth + 1))

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {
        "visited_count": len(visited),
        "traversal_order": traversal_order,
        "execution_time_ms": elapsed_ms
    }


def reconstruct_path(parent, target_node):
    """
    Reconstructs the shortest hop-by-hop connection chain using the BFS parent dictionary.
    """
    if target_node not in parent:
        return []
    path = []
    curr = target_node
    while curr is not None:
        path.append(curr)
        curr = parent[curr]
    path.reverse()
    return path


# Quick standalone test when run directly
if __name__ == "__main__":
    import pandas as pd
    df_e = pd.read_csv("data/employees.csv")
    df_d = pd.read_csv("data/devices.csv")
    df_l = pd.read_csv("data/login_logs.csv")

    _, adj, _, _, _ = build_infrastructure_graph(df_e, df_d, df_l, exclude_shared_gateway=True)
    res = custom_bfs(adj, "U001", max_depth=8)
    print("BFS Layers from U001:", res["layers"])
    print("Shortest Path U001 -> D150:", " -> ".join(reconstruct_path(res["parent"], "D150")))
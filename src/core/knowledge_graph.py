#!/usr/bin/env python3
"""知识图谱 — NetworkX 驱动的漏洞实体关联图，pickle 持久化"""

import json
import logging
import os
import pickle
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger("vuln-research-mcp")

DEFAULT_GRAPH_PATH = os.path.join(
    os.path.expanduser("~"), ".vuln-research-mcp", "knowledge_graph.pkl"
)

# Node types
NODE_TYPES = [
    "CVE", "CWE", "CPE", "Product", "Vendor",
    "Exploit", "ThreatActor", "Campaign", "TTP",
    "IOC", "Tool", "Infrastructure",
]

# Edge types
EDGE_TYPES = [
    "has_weakness",     # CVE → CWE
    "affects",          # CVE → CPE / Product
    "exploited_by",     # CVE → Exploit
    "attributed_to",    # Campaign → ThreatActor
    "uses_technique",   # ThreatActor → TTP
    "part_of_campaign", # Exploit → Campaign
    "targets",          # Campaign → Product/Vendor
    "related_to",       # 通用关联
    "mitigated_by",     # CVE → Patch
]


class KnowledgeGraph:
    """基于 NetworkX 的命运实体关系图谱"""

    def __init__(self, graph_path: str = None):
        self.graph_path = graph_path or DEFAULT_GRAPH_PATH
        self._graph = None
        self._load_or_create()

    def _load_or_create(self):
        try:
            import networkx as nx
        except ImportError:
            self._graph = self._fallback_graph()
            logger.warning("NetworkX 未安装，使用内存字典模式")
            return

        if os.path.exists(self.graph_path):
            try:
                with open(self.graph_path, "rb") as f:
                    self._graph = pickle.load(f)
                logger.info(f"知识图谱已加载: {self._graph.number_of_nodes()} 节点, {self._graph.number_of_edges()} 边")
                return
            except Exception as e:
                logger.warning(f"加载图谱失败: {e}, 创建新图")

        self._graph = nx.DiGraph()

    def _fallback_graph(self) -> dict:
        return {
            "nodes": defaultdict(dict),
            "edges": defaultdict(list),
        }

    def _is_nx(self) -> bool:
        try:
            import networkx as nx
            return isinstance(self._graph, nx.DiGraph)
        except ImportError:
            return False

    def add_node(self, node_id: str, node_type: str, properties: dict = None):
        if not node_id or not node_type:
            return
        properties = properties or {}
        properties["type"] = node_type

        if self._is_nx():
            import networkx as nx
            self._graph.add_node(node_id, **properties)
        else:
            self._graph["nodes"][node_id] = properties

    def add_edge(self, source: str, target: str, relation: str, properties: dict = None):
        if not source or not target:
            return
        properties = properties or {}
        properties["relation"] = relation

        if self._is_nx():
            import networkx as nx
            self._graph.add_edge(source, target, **properties)
        else:
            self._graph["edges"][source].append({
                "target": target,
                "relation": relation,
                **properties,
            })

    def traverse(self, start_node: str, max_depth: int = 3, relation_filter: list[str] = None) -> dict:
        """BFS 遍历图谱"""
        if self._is_nx():
            return self._traverse_nx(start_node, max_depth, relation_filter)
        return self._traverse_fallback(start_node, max_depth, relation_filter)

    def _traverse_nx(self, start_node: str, max_depth: int, relation_filter: list[str]) -> dict:
        import networkx as nx
        if start_node not in self._graph:
            return {"start": start_node, "nodes": [], "edges": [], "error": "节点不存在"}

        result = {"start": start_node, "paths": [], "nodes": {}, "edges": []}
        visited = set()

        def bfs(node, depth, path=None):
            if depth > max_depth or node in visited:
                return
            visited.add(node)
            path = (path or []) + [node]
            node_data = dict(self._graph.nodes[node])
            result["nodes"][node] = node_data

            for _, neighbor, edge_data in self._graph.out_edges(node, data=True):
                rel = edge_data.get("relation", "")
                if relation_filter and rel not in relation_filter:
                    continue
                result["edges"].append({
                    "source": node,
                    "target": neighbor,
                    "relation": rel,
                })
                new_path = path + [neighbor]
                bfs(neighbor, depth + 1, new_path)

            result["paths"].append(path)

        bfs(start_node, 0)
        return result

    def _traverse_fallback(self, start_node: str, max_depth: int, relation_filter: list[str]) -> dict:
        if start_node not in self._graph["nodes"]:
            return {"start": start_node, "nodes": [], "edges": [], "error": "节点不存在"}

        result = {"start": start_node, "paths": [[start_node]], "nodes": {start_node: self._graph["nodes"][start_node]}, "edges": []}
        visited = {start_node}
        queue = [(start_node, 0, [start_node])]

        while queue:
            node, depth, path = queue.pop(0)
            if depth >= max_depth:
                continue
            for edge in self._graph["edges"].get(node, []):
                target = edge["target"]
                rel = edge.get("relation", "")
                if relation_filter and rel not in relation_filter:
                    continue
                result["edges"].append({"source": node, "target": target, "relation": rel})
                if target not in visited:
                    visited.add(target)
                    result["nodes"][target] = self._graph["nodes"].get(target, {})
                    new_path = path + [target]
                    result["paths"].append(new_path)
                    queue.append((target, depth + 1, new_path))

        return result

    def neighbors(self, node_id: str) -> dict:
        if self._is_nx():
            import networkx as nx
            if node_id not in self._graph:
                return {"node": node_id, "inbound": [], "outbound": []}
            inbound = [{"source": u, "relation": d.get("relation", "")} for u, _, d in self._graph.in_edges(node_id, data=True)]
            outbound = [{"target": v, "relation": d.get("relation", "")} for _, v, d in self._graph.out_edges(node_id, data=True)]
            return {"node": node_id, "inbound": inbound, "outbound": outbound}
        else:
            outbound = [{"target": e["target"], "relation": e.get("relation", "")} for e in self._graph["edges"].get(node_id, [])]
            inbound = []
            for src, edges in self._graph["edges"].items():
                for e in edges:
                    if e["target"] == node_id:
                        inbound.append({"source": src, "relation": e.get("relation", "")})
            return {"node": node_id, "inbound": inbound, "outbound": outbound}

    def search(self, query: str) -> list[dict]:
        results = []
        if self._is_nx():
            for node, data in self._graph.nodes(data=True):
                if query.lower() in node.lower() or query.lower() in str(data).lower():
                    results.append({"id": node, "type": data.get("type", "unknown"), "properties": dict(data)})
        else:
            for node, data in self._graph["nodes"].items():
                if query.lower() in node.lower() or query.lower() in str(data).lower():
                    results.append({"id": node, "type": data.get("type", "unknown"), "properties": data})
        return results[:50]

    def stats(self) -> dict:
        if self._is_nx():
            import networkx as nx
            node_types = defaultdict(int)
            for _, data in self._graph.nodes(data=True):
                node_types[data.get("type", "unknown")] += 1
            edge_relations = defaultdict(int)
            for _, _, data in self._graph.edges(data=True):
                edge_relations[data.get("relation", "unknown")] += 1
            return {
                "total_nodes": self._graph.number_of_nodes(),
                "total_edges": self._graph.number_of_edges(),
                "node_types": dict(node_types),
                "edge_relations": dict(edge_relations),
            }
        else:
            node_types = defaultdict(int)
            for _, data in self._graph["nodes"].items():
                node_types[data.get("type", "unknown")] += 1
            edge_count = sum(len(v) for v in self._graph["edges"].values())
            edge_relations = defaultdict(int)
            for edges in self._graph["edges"].values():
                for e in edges:
                    edge_relations[e.get("relation", "unknown")] += 1
            return {
                "total_nodes": len(self._graph["nodes"]),
                "total_edges": edge_count,
                "node_types": dict(node_types),
                "edge_relations": dict(edge_relations),
            }

    def save(self):
        if self._is_nx():
            os.makedirs(os.path.dirname(self.graph_path), exist_ok=True)
            import networkx as nx
            with open(self.graph_path, "wb") as f:
                pickle.dump(self._graph, f)
            logger.info(f"知识图谱已保存: {self._graph.number_of_nodes()} 节点")

    def export_json(self, path: str):
        data = {
            "nodes": {},
            "edges": [],
        }
        if self._is_nx():
            import networkx as nx
            for node, d in self._graph.nodes(data=True):
                data["nodes"][node] = dict(d)
            for u, v, d in self._graph.edges(data=True):
                data["edges"].append({"source": u, "target": v, **d})
        else:
            data["nodes"] = dict(self._graph["nodes"])
            for src, edges in self._graph["edges"].items():
                for e in edges:
                    data["edges"].append({"source": src, **e})

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"图谱导出到: {path}")


# 全局实例
_graph: Optional[KnowledgeGraph] = None


def get_graph() -> KnowledgeGraph:
    global _graph
    if _graph is None:
        _graph = KnowledgeGraph()
    return _graph

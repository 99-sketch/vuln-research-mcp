#!/usr/bin/env python3
"""知识图谱查询工具"""

import json
import logging

logger = logging.getLogger("vuln-research-mcp")


async def graph_traverse(start_node: str, max_depth: int = 3, relation_filter: str = None) -> dict:
    """BFS 遍历知识图谱"""
    try:
        from src.core.knowledge_graph import get_graph
        graph = get_graph()
        filters = relation_filter.split(",") if relation_filter else None
        return graph.traverse(start_node, max_depth=max_depth, relation_filter=filters)
    except Exception as e:
        return {"error": str(e), "start_node": start_node}


async def graph_neighbors(node_id: str) -> dict:
    """查询节点邻居"""
    try:
        from src.core.knowledge_graph import get_graph
        graph = get_graph()
        return graph.neighbors(node_id)
    except Exception as e:
        return {"error": str(e), "node_id": node_id}


async def graph_search(query: str) -> dict:
    """搜索知识图谱节点"""
    try:
        from src.core.knowledge_graph import get_graph
        graph = get_graph()
        results = graph.search(query)
        return {"query": query, "matches": results, "total": len(results)}
    except Exception as e:
        return {"error": str(e), "query": query}


async def graph_stats() -> dict:
    """知识图谱统计"""
    try:
        from src.core.knowledge_graph import get_graph
        graph = get_graph()
        return graph.stats()
    except Exception as e:
        return {"error": str(e)}


async def graph_add_relation(source: str, target: str, relation: str, source_type: str = "", target_type: str = "") -> dict:
    """添加图谱关系"""
    try:
        from src.core.knowledge_graph import get_graph
        graph = get_graph()
        graph.add_node(source, source_type or "Unknown")
        graph.add_node(target, target_type or "Unknown")
        graph.add_edge(source, target, relation)
        graph.save()
        return {"status": "ok", "source": source, "target": target, "relation": relation}
    except Exception as e:
        return {"error": str(e)}

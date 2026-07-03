# src/tools/cvss_tool.py
"""CVSS v3.1 评分计算器 - 符合 FIRST 规范"""

import math


def _parse_cvss_vector(vector: str) -> dict:
    """解析 CVSS v3.1 vector 字符串为参数字典"""
    metrics = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    mapping = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S": "scope",
        "C": "confidentiality",
        "I": "integrity",
        "A": "availability",
    }
    value_map = {
        "attack_vector": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
        "attack_complexity": {"L": "LOW", "H": "HIGH"},
        "privileges_required": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "user_interaction": {"N": "NONE", "R": "REQUIRED"},
        "scope": {"U": "UNCHANGED", "C": "CHANGED"},
        "confidentiality": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "integrity": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "availability": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    }
    for part in parts:
        if ":" not in part:
            continue
        metric, value = part.split(":", 1)
        key = mapping.get(metric)
        if key:
            metrics[key] = value_map[key].get(value, value)
    return metrics


def _round_up(value: float, precision: int) -> float:
    """按 CVSS 规范向上取整"""
    multiplier = 10 ** precision
    return math.ceil(value * multiplier - 0.0000005) / multiplier


def _compute_cvss_v3_1(metrics: dict) -> dict:
    """按 FIRST CVSS v3.1 规范计算基础分数"""
    av_map = {"NETWORK": 0.85, "ADJACENT_NETWORK": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
    ac_map = {"LOW": 0.77, "HIGH": 0.44}
    pr_map = {
        "NONE": {"UNCHANGED": 0.85, "CHANGED": 0.85},
        "LOW": {"UNCHANGED": 0.62, "CHANGED": 0.68},
        "HIGH": {"UNCHANGED": 0.27, "CHANGED": 0.50},
    }
    ui_map = {"NONE": 0.85, "REQUIRED": 0.62}
    cia_map = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

    av = av_map.get(metrics.get("attack_vector"), 0)
    ac = ac_map.get(metrics.get("attack_complexity"), 0)
    pr = pr_map.get(metrics.get("privileges_required"), {}).get(metrics.get("scope"), 0)
    ui = ui_map.get(metrics.get("user_interaction"), 0)
    scope_changed = metrics.get("scope") == "CHANGED"
    c = cia_map.get(metrics.get("confidentiality"), 0)
    i = cia_map.get(metrics.get("integrity"), 0)
    a = cia_map.get(metrics.get("availability"), 0)

    # 1. Impact Sub-Score (ISS)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # 2. Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # 3. Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # 4. Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10)
        else:
            base_score = min(impact + exploitability, 10)

    base_score = _round_up(base_score, 1)

    # 5. 严重等级
    if base_score == 0.0:
        severity = "NONE"
    elif base_score < 4.0:
        severity = "LOW"
    elif base_score < 7.0:
        severity = "MEDIUM"
    elif base_score < 9.0:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    vector = (
        f"CVSS:3.1/AV:{metrics.get('attack_vector')[0]}/"
        f"AC:{metrics.get('attack_complexity')[0]}/"
        f"PR:{metrics.get('privileges_required')[0]}/"
        f"UI:{metrics.get('user_interaction')[0]}/"
        f"S:{metrics.get('scope')[0]}/"
        f"C:{metrics.get('confidentiality')[0]}/"
        f"I:{metrics.get('integrity')[0]}/"
        f"A:{metrics.get('availability')[0]}"
    )

    return {
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 3),
        "exploitability": round(exploitability, 3),
        "vector": vector,
        "metrics": {
            "AV": metrics.get("attack_vector"),
            "AC": metrics.get("attack_complexity"),
            "PR": metrics.get("privileges_required"),
            "UI": metrics.get("user_interaction"),
            "S": metrics.get("scope"),
            "C": metrics.get("confidentiality"),
            "I": metrics.get("integrity"),
            "A": metrics.get("availability"),
        },
        "note": "基于 FIRST CVSS v3.1 规范计算（完整 Base Score 算法）",
    }


async def cvss_calculator(**kwargs) -> dict:
    """计算 CVSS v3.1 评分"""
    vector = kwargs.get("vector")
    if vector and isinstance(vector, str) and vector.startswith("CVSS:3.1/"):
        kwargs = _parse_cvss_vector(vector)
    elif kwargs.get("vector"):
        return {"error": "vector 格式不正确，必须以 CVSS:3.1/ 开头"}

    required = [
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope", "confidentiality", "integrity", "availability",
    ]
    missing = [p for p in required if p not in kwargs or kwargs[p] is None]
    if missing:
        return {"error": f"缺少参数: {', '.join(missing)}。或者传入完整 vector 字符串"}

    return _compute_cvss_v3_1(kwargs)

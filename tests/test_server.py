#!/usr/bin/env python3
"""
测试脚本：验证 Vulnerability Research MCP Server 功能
"""

import asyncio
import json
import sys
import os

# 添加 src 目录到 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from server import server, search_cve, get_cve_details, cvss_calculator

async def test_search_cve():
    """测试 search_cve 工具"""
    print("="*60)
    print("测试 1: search_cve")
    print("="*60)
    
    try:
        result = await search_cve(keyword="Log4j", max_results=5)
        print(f"✅ 成功搜索 CVE")
        print(f"总结果数: {result['total_results']}")
        print(f"返回漏洞数: {len(result['vulnerabilities'])}")
        
        if result['vulnerabilities']:
            first = result['vulnerabilities'][0]
            print(f"\n第一个漏洞:")
            print(f"  CVE ID: {first['cve_id']}")
            print(f"  CVSS 评分: {first['cvss_score']}")
            print(f"  严重等级: {first['severity']}")
            
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")

async def test_get_cve_details():
    """测试 get_cve_details 工具"""
    print("\n" + "="*60)
    print("测试 2: get_cve_details")
    print("="*60)
    
    try:
        result = await get_cve_details(cve_id="CVE-2021-44228")
        print(f"✅ 成功获取 CVE 详情")
        print(f"CVE ID: {result['cve_id']}")
        print(f"状态: {result['status']}")
        print(f"发布日期: {result['published']}")
        print(f"描述: {result['description'][:100]}...")
        
        if 'cvss_score' in result.get('metrics', {}):
            print(f"CVSS 评分: {result['metrics']['cvss_score']}")
            
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")

async def test_cvss_calculator():
    """测试 cvss_calculator 工具"""
    print("\n" + "="*60)
    print("测试 3: cvss_calculator")
    print("="*60)
    
    try:
        result = await cvss_calculator(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            scope="UNCHANGED",
            confidentiality="HIGH",
            integrity="HIGH",
            availability="HIGH"
        )
        print(f"✅ 成功计算 CVSS 评分")
        print(f"基础评分: {result['base_score']}")
        print(f"严重等级: {result['severity']}")
        print(f"向量: {json.dumps(result['vector'], indent=2)}")
        
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")

async def main():
    """运行所有测试"""
    print("\n" + "🧪 Vulnerability Research MCP Server 测试套件")
    print("="*60 + "\n")
    
    # 运行测试
    await test_search_cve()
    await test_get_cve_details()
    await test_cvss_calculator()
    
    print("\n" + "="*60)
    print("✅ 所有测试完成")
    print("="*60 + "\n")

if __name__ == "__main__":
    asyncio.run(main())

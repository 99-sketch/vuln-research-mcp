#!/usr/bin/env python3
"""交互式 CLI — Rich-powered 终端界面"""

import json
import os
import sys

HAS_RICH = False
Console = None
Table = None
Panel = None
Syntax = None
Progress = None
SpinnerColumn = None
TextColumn = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress, SpinnerColumn, TextColumn
    HAS_RICH = True
except ImportError:
    pass


class VulnResearchCLI:
    def __init__(self, tool_registry, workflow_engine, export_pipeline, knowledge_graph):
        self.tool_registry = tool_registry
        self.workflow_engine = workflow_engine
        self.export_pipeline = export_pipeline
        self.knowledge_graph = knowledge_graph
        self.console = Console() if HAS_RICH else None

    def _print(self, text):
        if self.console:
            self.console.print(text)
        else:
            print(text)

    def list_tools(self):
        tools = self.tool_registry.list_all()
        if HAS_RICH:
            table = Table(title="Available Tools")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="green")
            for t in tools:
                table.add_row(t["name"], t["description"])
            self._print(table)
        else:
            for t in tools:
                print(f"  {t['name']}: {t['description']}")

    def list_workflows(self):
        from src.workflow.presets import BUILTIN_WORKFLOWS
        if HAS_RICH:
            table = Table(title="Preset Workflows")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="green")
            for name, wf in BUILTIN_WORKFLOWS.items():
                table.add_row(name, wf["description"])
            self._print(table)
        else:
            for name, wf in BUILTIN_WORKFLOWS.items():
                print(f"  {name}: {wf['description']}")

    def show_shortcuts(self):
        shortcuts = {
            "cve <id>": "get_cve_details",
            "search <kw>": "search_cve",
            "assess <id>": "vulnerability_assess",
            "kev <id>": "check_kev",
            "epss <id>": "get_epss_score",
            "exploit <kw>": "search_exploit",
            "nuclei <kw>": "find_nuclei_template",
            "ip <ip>": "geolocate_ip",
            "dns <domain>": "query_dns",
            "http <url>": "check_http_headers",
            "ports <target>": "scan_ports",
            "cpe <product>": "cpe_lookup",
            "fingerprint <banner>": "service_fingerprint",
            "graph-traverse <node>": "graph_traverse",
            "graph-search <kw>": "graph_search",
            "graph-stats": "graph_stats",
        }
        if HAS_RICH:
            table = Table(title="Shortcut Commands")
            table.add_column("Shortcut", style="cyan")
            table.add_column("Tool", style="yellow")
            for s, t in shortcuts.items():
                table.add_row(s, t)
            self._print(table)
        else:
            for s, t in shortcuts.items():
                print(f"  {s:30s} -> {t}")

    async def run_workflow(self, workflow_name: str, target: str, output_formats: list[str] = None, output_dir: str = None):
        from src.workflow.presets import BUILTIN_WORKFLOWS
        wf_def = BUILTIN_WORKFLOWS.get(workflow_name)
        if not wf_def:
            self._print(f"[ERROR] Unknown workflow: {workflow_name}")
            self._print(f"Available: {list(BUILTIN_WORKFLOWS.keys())}")
            return

        self._print(f"Running workflow: {wf_def['name']} | Target: {target}")
        result = await self.workflow_engine.execute(
            workflow_id=workflow_name,
            steps=wf_def["steps"],
            initial_context={"context": {"target": target}},
        )
        self._print_result(result)

        if output_formats and output_dir:
            all_vulns = []
            for output in result.get("outputs", {}).values():
                if isinstance(output, dict):
                    all_vulns.append(output)
            if all_vulns:
                files = self.export_pipeline.export_to_files(all_vulns, output_formats, output_dir)
                self._print(f"Exported: {json.dumps(files, indent=2)}")

    def _print_result(self, result):
        if HAS_RICH:
            status_color = "green" if result["status"] == "success" else "yellow" if result["status"] == "partial" else "red"
            self._print(f"Status: [{status_color}]{result['status']}[/{status_color}]")
            self._print(f"Completed: {result['steps_completed']} | Failed: {result['steps_failed']}")
            table = Table(title="Step Results")
            table.add_column("Step", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Duration")
            for name, r in result.get("results", {}).items():
                status_icon = "[green]OK[/green]" if r["status"] == "success" else "[red]FAIL[/red]" if r["status"] == "failed" else "[dim]SKIP[/dim]"
                table.add_row(name, status_icon, f"{r.get('duration_ms', 0):.0f}ms")
            self._print(table)
        else:
            print(f"Status: {result['status']}")
            print(f"Steps: {result['steps_completed']} ok, {result['steps_failed']} failed")
            for name, r in result.get("results", {}).items():
                status = "OK" if r["status"] == "success" else "FAIL"
                print(f"  [{status}] {name}")

    async def tool_call(self, tool_name: str, **kwargs):
        tool_def = self.tool_registry.resolve(tool_name)
        if not tool_def:
            self._print(f"[ERROR] Unknown tool: {tool_name}")
            return
        result = await tool_def.handler(**{k: v for k, v in kwargs.items() if v is not None})
        formatted = json.dumps(result, indent=2, ensure_ascii=False)
        if HAS_RICH and isinstance(formatted, str):
            self._print(Syntax(formatted, "json"))
        else:
            self._print(formatted)
        return result

    async def interactive(self):
        if HAS_RICH:
            self._print(Panel("Vulnerability Research MCP v3.0 — Interactive CLI", title="vuln-research-mcp"))
        else:
            self._print("=== Vuln Research MCP v3.0 — Interactive CLI ===")
        self._print("Type 'help' for commands, 'exit' to quit")

        while True:
            try:
                prompt = "vrmcp> " if HAS_RICH else "\nvrmcp> "
                line = input(prompt).strip()
                if not line:
                    continue

                if line == "exit":
                    break
                elif line == "help":
                    self._print("Commands:")
                    self._print("  tools              List all tools")
                    self._print("  workflows          List preset workflows")
                    self._print("  shortcuts          List shortcut commands")
                    self._print("  tool <name> <args> Call a tool directly")
                    self._print("  run <name> <target> Run a preset workflow")
                    self._print("  info <name>        Show tool parameter info")
                    self._print("  graph              Show knowledge graph stats")
                    self._print("  exit               Quit")
                elif line == "tools":
                    self.list_tools()
                elif line == "workflows":
                    self.list_workflows()
                elif line == "shortcuts":
                    self.show_shortcuts()
                elif line == "graph":
                    stats = self.knowledge_graph.stats()
                    self._print(json.dumps(stats, indent=2))
                elif line.startswith("info "):
                    tool_name = line[5:].strip()
                    tool_def = self.tool_registry.resolve(tool_name)
                    if tool_def:
                        self._print(json.dumps(tool_def.input_schema, indent=2))
                    else:
                        self._print(f"Unknown tool: {tool_name}")
                elif line.startswith("tool "):
                    parts = _parse_args(line[5:])
                    if parts:
                        await self.tool_call(parts[0], **{k: v for k, v in parts[1:] if v is not None})
                    else:
                        self._print("Usage: tool <name> [key=value ...]")
                elif line.startswith("run "):
                    parts = line[4:].split()
                    if len(parts) >= 2:
                        await self.run_workflow(parts[0], parts[1], output_formats=["json", "markdown"], output_dir=os.path.join(os.getcwd(), "reports"))
                    else:
                        self._print("Usage: run <workflow_name> <target>")
                elif line.startswith("cve "):
                    await self.tool_call("get_cve_details", cve_id=line[4:])
                elif line.startswith("search "):
                    await self.tool_call("search_cve", keyword=line[7:])
                elif line.startswith("assess "):
                    await self.tool_call("vulnerability_assess", cve_id=line[7:])
                elif line.startswith("kev "):
                    await self.tool_call("check_kev", cve_id=line[4:])
                elif line.startswith("epss "):
                    await self.tool_call("get_epss_score", cve_id=line[5:])
                elif line.startswith("exploit "):
                    await self.tool_call("search_exploit", query=line[8:])
                elif line.startswith("nuclei "):
                    await self.tool_call("find_nuclei_template", tags=line[7:])
                elif line.startswith("ip "):
                    await self.tool_call("geolocate_ip", ip=line[3:])
                elif line.startswith("dns "):
                    await self.tool_call("query_dns", domain=line[4:])
                elif line.startswith("http "):
                    await self.tool_call("check_http_headers", url=line[5:])
                elif line.startswith("ports "):
                    await self.tool_call("scan_ports", target=line[6:])
                elif line.startswith("cpe "):
                    await self.tool_call("cpe_lookup", product=line[4:])
                elif line.startswith("fingerprint "):
                    await self.tool_call("service_fingerprint", banner=line[12:])
                elif line.startswith("graph-traverse "):
                    await self.tool_call("graph_traverse", start_node=line[15:])
                elif line.startswith("graph-search "):
                    await self.tool_call("graph_search", query=line[13:])
                elif line.startswith("graph-stats"):
                    await self.tool_call("graph_stats")
                elif line == "vrmcp>":
                    continue
                else:
                    self._print(f"Unknown command: {line}  (type 'help' for commands)")
            except KeyboardInterrupt:
                self._print("\nBye.")
                break
            except EOFError:
                break


def _parse_args(args_str: str) -> list:
    """解析 'tool_name key1=val1 key2=val2 positional_arg' 格式"""
    parts = args_str.split()
    if not parts:
        return []
    result = [parts[0]]
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            try:
                v = int(v)
            except ValueError:
                try:
                    v = float(v)
                except ValueError:
                    pass
            result.append((k, v))
        else:
            result.append((p, p))
    return result

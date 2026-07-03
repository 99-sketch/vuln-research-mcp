"""Tests for Scanner Integration Tools."""

import json
import tempfile
import os
import pytest
from src.tools.scanner_tools import (
    generate_nuclei_command, search_metasploit, search_sploit,
    NmapPort, NmapHost,
)


class TestGenerateNucleiCommand:
    def test_basic_command(self):
        cmd = generate_nuclei_command("https://example.com")
        assert "nuclei" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd

    def test_with_templates(self):
        cmd = generate_nuclei_command(
            "https://example.com",
            templates=["cves/2021/CVE-2021-44228.yaml", "technologies/tech-detect.yaml"],
        )
        assert "-t cves/2021/CVE-2021-44228.yaml" in cmd
        assert "-t technologies/tech-detect.yaml" in cmd

    def test_with_severity(self):
        cmd = generate_nuclei_command(
            "https://example.com",
            severity="critical,high",
        )
        assert "-severity critical,high" in cmd

    def test_with_output_path(self):
        cmd = generate_nuclei_command(
            "https://example.com",
            output_path="/tmp/nuclei-output.json",
        )
        assert "-json-export /tmp/nuclei-output.json" in cmd

    def test_with_extra_args(self):
        cmd = generate_nuclei_command(
            "https://example.com",
            extra_args=["-timeout", "30", "-retries", "2"],
        )
        assert "-timeout 30" in cmd
        assert "-retries 2" in cmd

    def test_always_silent_no_color(self):
        cmd = generate_nuclei_command("https://example.com")
        assert "-silent" in cmd
        assert "-no-color" in cmd

    def test_full_command(self):
        cmd = generate_nuclei_command(
            "https://example.com",
            templates=["cves/critical"],
            severity="critical",
            output_path="out.json",
            extra_args=["-stats"],
        )
        assert cmd.startswith("nuclei")
        assert "nuclei" == cmd.split()[0]


class TestSearchMetasploit:
    def test_search_returns_list(self):
        results = search_metasploit("log4shell")
        assert isinstance(results, list)

    def test_search_nonexistent(self):
        results = search_metasploit("xyzabc123nonexistentmodule999")
        assert isinstance(results, list)


class TestSearchSploit:
    def test_search_returns_list(self):
        results = search_sploit("apache")
        assert isinstance(results, list)

    def test_search_with_version(self):
        results = search_sploit("apache 2.4.49")
        assert isinstance(results, list)


class TestNmapHost:
    def test_create_nmap_host_empty(self):
        host = NmapHost(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.hostname == ""
        assert host.ports == []
        assert host.status == "up"

    def test_create_nmap_host_full(self):
        host = NmapHost(
            ip="10.0.0.1", hostname="web01.example.com",
            os="Linux 4.15", os_accuracy=95,
        )
        assert host.os == "Linux 4.15"
        assert host.os_accuracy == 95


class TestNmapPort:
    def test_create_nmap_port(self):
        port = NmapPort(port=443, protocol="tcp", state="open",
                        service="https", version="1.20.1",
                        product="nginx", banner="nginx/1.20.1")
        assert port.port == 443
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service == "https"
        assert port.product == "nginx"

    def test_nmap_port_scripts(self):
        port = NmapPort(port=80, protocol="tcp", state="open",
                        scripts=[{"id": "http-title", "output": "Welcome"}])
        assert len(port.scripts) == 1
        assert port.scripts[0]["id"] == "http-title"

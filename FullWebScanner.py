#!/usr/bin/env python3
import asyncio
import aiofiles
import subprocess
import re
import os
import sys
import concurrent.futures
import time
from dataclasses import dataclass
from typing import List

@dataclass
class Vulnerability:
    type: str
    description: str
    confidence: str
    tool: str

class AsyncWebVulnerabilityAnalyzer:
    def __init__(self, target):
        self.target = target
        self.results = {
            'server_info': {},
            'nikto_findings': [],
            'directories': [],
            'potential_vulns': [],
            'scan_times': {}
        }
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    
    async def run_parallel_scans(self):
        tasks = [
            self.run_nmap_scan(),
            self.run_nikto_scan(),
            self.run_gobuster_scan(),
            self.run_dirsearch_scan(),
            self.check_common_endpoints()
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def run_nmap_scan(self):
        start_time = time.time()
        print("[→] Starting Nmap scan...")
        try:
            loop = asyncio.get_event_loop()
            cmd = f"nmap -sV -p 80,443,8080,8443 --script http-enum,http-headers {self.target}"
            result = await loop.run_in_executor(
                self.executor, 
                lambda: subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            )
            await self.parse_nmap_output(result.stdout)
            self.results['scan_times']['nmap'] = time.time() - start_time
            print("[✓] Nmap scan completed")
        except Exception as e:
            print(f"[-] Nmap scan failed: {e}")
    
    async def parse_nmap_output(self, output):
        server_match = re.search(r'Server: ([^\n]+)', output)
        if server_match:
            self.results['server_info']['server'] = server_match.group(1)
        tech_matches = re.findall(r'([^:]+): (.+)', output)
        for match in tech_matches:
            self.results['server_info'][match[0].strip()] = match[1].strip()
    
    async def run_nikto_scan(self):
        start_time = time.time()
        print("[→] Starting Nikto scan...")
        try:
            loop = asyncio.get_event_loop()
            cmd = f"nikto -h {self.target} -o nikto_scan.txt -Format txt"
            await loop.run_in_executor(
                self.executor,
                lambda: subprocess.run(cmd, shell=True, timeout=600)
            )
            async with aiofiles.open('nikto_scan.txt', 'r') as f:
                content = await f.read()
                await self.parse_nikto_output(content)
            self.results['scan_times']['nikto'] = time.time() - start_time
            print("[✓] Nikto scan completed")
        except Exception as e:
            print(f"[-] Nikto scan failed: {e}")
    
    async def parse_nikto_output(self, output):
        vuln_patterns = {
            'XSS': r'Cross-Site Scripting|XSS',
            'SQLi': r'SQL injection|SQLi',
            'LFI': r'File inclusion|directory traversal',
            'RCE': r'command execution|RCE',
            'Info Disclosure': r'information disclosure',
            'Misconfiguration': r'misconfigured|configuration error'
        }
        lines = output.split('\n')
        for line in lines:
            if '+ ' in line and any(keyword in line for keyword in ['found', 'vulnerable', 'may be']):
                self.results['nikto_findings'].append(line.strip())
                for vuln_type, pattern in vuln_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        self.results['potential_vulns'].append(
                            Vulnerability(
                                type=vuln_type,
                                description=line.strip(),
                                confidence='medium',
                                tool='nikto'
                            )
                        )
    
    async def run_gobuster_scan(self):
        start_time = time.time()
        print("[→] Starting Gobuster scan...")
        try:
            loop = asyncio.get_event_loop()
            wordlists = [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/dirb/big.txt'
            ]
            for wordlist in wordlists:
                if os.path.exists(wordlist):
                    cmd = f"gobuster dir -u {self.target} -w {wordlist} -o gobuster_scan.txt -q -t 50"
                    await loop.run_in_executor(
                        self.executor,
                        lambda: subprocess.run(cmd, shell=True, timeout=600)
                    )
                    async with aiofiles.open('gobuster_scan.txt', 'r') as f:
                        content = await f.read()
                        await self.parse_gobuster_output(content)
                    break
            self.results['scan_times']['gobuster'] = time.time() - start_time
            print("[✓] Gobuster scan completed")
        except Exception as e:
            print(f"[-] Gobuster scan failed: {e}")
    
    async def parse_gobuster_output(self, output):
        lines = output.split('\n')
        for line in lines:
            if 'Status:' in line and '200' in line:
                dir_match = re.search(r'/([^\s]+)\s+\(Status:', line)
                if dir_match:
                    directory = dir_match.group(1)
                    self.results['directories'].append(directory)
    
    async def run_dirsearch_scan(self):
        start_time = time.time()
        print("[→] Starting Dirsearch scan...")
        try:
            loop = asyncio.get_event_loop()
            cmd = f"dirsearch -u {self.target} -e php,html,txt,js,json -o dirsearch_scan.txt -q -t 50"
            await loop.run_in_executor(
                self.executor,
                lambda: subprocess.run(cmd, shell=True, timeout=600)
            )
            if os.path.exists('dirsearch_scan.txt'):
                async with aiofiles.open('dirsearch_scan.txt', 'r') as f:
                    content = await f.read()
                    await self.parse_dirsearch_output(content)
            self.results['scan_times']['dirsearch'] = time.time() - start_time
            print("[✓] Dirsearch scan completed")
        except Exception as e:
            print(f"[-] Dirsearch scan failed: {e}")
    
    async def parse_dirsearch_output(self, output):
        lines = output.split('\n')
        for line in lines:
            if '200' in line and 'Size:' in line:
                dir_match = re.search(r'200\s+-\s+[\d]+\w+\s+-\s+/([^\s]+)', line)
                if dir_match:
                    directory = dir_match.group(1)
                    if directory not in self.results['directories']:
                        self.results['directories'].append(directory)
    
    async def check_common_endpoints(self):
        start_time = time.time()
        print("[→] Checking common endpoints...")
        common_paths = [
            '/admin', '/login', '/config', '/backup', '/api', '/phpinfo.php',
            '/.git/', '/wp-admin/', '/phpmyadmin/', '/server-status'
        ]
        try:
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                tasks = []
                for path in common_paths:
                    url = f"{self.target.rstrip('/')}{path}"
                    tasks.append(self.check_endpoint(session, url, path))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if result and isinstance(result, tuple):
                        path, status = result
                        if status == 200:
                            self.results['directories'].append(path.lstrip('/'))
            self.results['scan_times']['endpoints'] = time.time() - start_time
            print("[✓] Common endpoints check completed")
        except ImportError:
            print("[-] aiohttp not installed")
        except Exception as e:
            print(f"[-] Endpoint check failed: {e}")
    
    async def check_endpoint(self, session, url, path):
        try:
            async with session.get(url) as response:
                return (path, response.status)
        except:
            return None
    
    async def analyze_technologies(self):
        server = self.results['server_info'].get('server', '').lower()
        tech_vulns = {
            'apache': ['mod_negotiation bypass', '.htaccess misconfiguration'],
            'nginx': ['path traversal', 'alias misconfiguration'],
            'iis': ['shortname enumeration', 'Tilde enumeration'],
            'php': ['LFI/RFI', 'PHP wrappers', 'deserialization'],
            'node.js': ['prototype pollution', 'RCE through eval'],
        }
        for tech, vulns in tech_vulns.items():
            if tech in server:
                for vuln in vulns:
                    self.results['potential_vulns'].append(
                        Vulnerability(
                            type=f'{tech.upper()} Specific',
                            description=f'{tech} - possible {vuln}',
                            confidence='medium',
                            tool='technology_analysis'
                        )
                    )
        dangerous_dirs = ['admin', 'backup', 'config', 'sql', 'phpmyadmin']
        for directory in self.results['directories']:
            if any(danger_dir in directory for danger_dir in dangerous_dirs):
                self.results['potential_vulns'].append(
                    Vulnerability(
                        type='Sensitive Directory Exposure',
                        description=f'Found sensitive directory: /{directory}',
                        confidence='high',
                        tool='directory_scan'
                    )
                )
    
    def generate_report(self):
        print("\n" + "="*50)
        print("WEB VULNERABILITY ANALYSIS REPORT")
        print("="*50)
        print(f"\nTarget: {self.target}")
        print("\n[SERVER INFORMATION]")
        for key, value in self.results['server_info'].items():
            print(f"  {key}: {value}")
        print(f"\n[DIRECTORIES FOUND] ({len(self.results['directories'])} total)")
        for dir in sorted(self.results['directories'])[:10]:
            print(f"  /{dir}")
        print(f"\n[POTENTIAL VULNERABILITIES] ({len(self.results['potential_vulns'])} found)")
        if self.results['potential_vulns']:
            for vuln in self.results['potential_vulns']:
                print(f"  [{vuln.confidence.upper()}] {vuln.type}: {vuln.description}")
        else:
            print("  No obvious vulnerabilities detected")
        print("\n[SCAN TIMES]")
        for tool, scan_time in self.results['scan_times'].items():
            print(f"  {tool}: {scan_time:.2f}s")
    
    async def cleanup(self):
        temp_files = ['nikto_scan.txt', 'gobuster_scan.txt', 'dirsearch_scan.txt']
        for file in temp_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass
        self.executor.shutdown(wait=True)

async def main():
    if len(sys.argv) != 2:
        print("Usage: python3 async_web_analyzer.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    analyzer = AsyncWebVulnerabilityAnalyzer(target)
    try:
        start_time = time.time()
        await analyzer.run_parallel_scans()
        await analyzer.analyze_technologies()
        analyzer.generate_report()
        total_time = time.time() - start_time
        print(f"\nTotal scan time: {total_time:.2f}s")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
    finally:
        await analyzer.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy-checker-cli
检测 SOCKS5 / HTTP 代理的连通性、延迟、匿名度与出口 IP。
纯 Python3，无第三方依赖。
"""

__version__ = '1.0.0'

import argparse
import json
import re
import socket
import sys
import time
from urllib.parse import urlparse


def parse_proxy(url):
    u = urlparse(url)
    if not u.scheme or not u.hostname or not u.port:
        raise ValueError(f'代理格式错误: {url}')
    return u.scheme.lower(), u.hostname, u.port, u.username, u.password


def socks5_connect(proxy_host, proxy_port, target_host, target_port, username=None, password=None, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))

    auth_methods = [0x02, 0x00] if username else [0x00]
    sock.sendall(b'\x05' + bytes([len(auth_methods)]) + bytes(auth_methods))
    resp = sock.recv(2)
    if resp[0] != 0x05:
        raise ConnectionError('SOCKS5 握手失败')

    if resp[1] == 0x02:
        if not username:
            raise ConnectionError('代理要求认证')
        cred = bytes([len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
        sock.sendall(b'\x01' + cred)
        auth_resp = sock.recv(2)
        if auth_resp[1] != 0x00:
            raise ConnectionError('SOCKS5 认证失败')
    elif resp[1] != 0x00:
        raise ConnectionError('SOCKS5 不接受无认证')

    addr = socket.inet_aton(target_host) if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target_host) else b'\x00'
    req = b'\x05\x01\x00' + (b'\x01' + addr if addr != b'\x00' else b'\x03' + bytes([len(target_host)]) + target_host.encode()) + target_port.to_bytes(2, 'big')
    sock.sendall(req)
    r = sock.recv(10)
    if r[1] != 0x00:
        raise ConnectionError(f'SOCKS5 连接失败: {r[1]}')
    return sock


def http_tunnel_connect(proxy_host, proxy_port, target_host, target_port, username=None, password=None, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))
    auth = ''
    if username:
        import base64
        auth = 'Proxy-Authorization: Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode() + '\r\n'
    req = f'CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth}\r\n'
    sock.sendall(req.encode())
    resp = sock.recv(1024).decode('utf-8', 'ignore')
    if not resp.startswith('HTTP/1.1 2'):
        raise ConnectionError(f'HTTP 隧道建立失败: {resp.splitlines()[0]}')
    return sock


def send_http_get(sock, host, path='/json'):
    req = f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxy-checker-cli/{__version__}\r\nAccept: */*\r\nConnection: close\r\n\r\n'
    sock.sendall(req.encode())
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode('utf-8', 'ignore')


def parse_json_response(raw):
    idx = raw.find('\r\n\r\n')
    if idx != -1:
        raw = raw[idx+4:]
    try:
        return json.loads(raw)
    except Exception:
        return {}


def check_anonymity(headers):
    h = {k.lower(): v for k, v in headers.items()}
    leak_headers = ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'client-ip']
    if any(k in h for k in leak_headers):
        if 'via' in h or 'proxy-connection' in h:
            return 'transparent'
        return 'anonymous'
    return 'elite'


def extract_headers(raw):
    headers = {}
    lines = raw.splitlines()
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
    return headers


def check_proxy(proxy_url, timeout=10):
    t0 = time.time()
    result = {'proxy': proxy_url, 'ok': False, 'latency_ms': None, 'exit_ip': None, 'anonymity': None, 'error': None}
    try:
        scheme, host, port, user, pwd = parse_proxy(proxy_url)
        target = 'httpbin.org'
        target_port = 443 if scheme == 'https' else 80

        if scheme == 'socks5':
            sock = socks5_connect(host, port, target, target_port, user, pwd, timeout)
        elif scheme in ('http', 'https'):
            sock = http_tunnel_connect(host, port, target, target_port, user, pwd, timeout)
        else:
            raise ValueError(f'不支持的协议: {scheme}')

        raw = send_http_get(sock, target, '/ip')
        headers = extract_headers(raw)
        body = parse_json_response(raw)
        sock.close()

        result['latency_ms'] = round((time.time() - t0) * 1000, 1)
        result['ok'] = True
        result['exit_ip'] = body.get('origin', '')
        result['anonymity'] = check_anonymity(headers)
    except Exception as e:
        result['error'] = str(e)
    return result


def main():
    parser = argparse.ArgumentParser(description='代理检测工具')
    parser.add_argument('--version', action='version', version=f'proxy-checker-cli {__version__}')
    parser.add_argument('--proxy', '-p', help='单个代理地址，如 socks5://127.0.0.1:1080')
    parser.add_argument('--list', '-l', help='代理列表文件，每行一个代理')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='超时时间（秒）')
    parser.add_argument('--output', '-o', help='结果输出 JSON 文件')
    args = parser.parse_args()

    proxies = []
    if args.proxy:
        proxies.append(args.proxy)
    if args.list:
        with open(args.list, 'r', encoding='utf-8') as f:
            proxies.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])

    if not proxies:
        parser.print_help()
        sys.exit(1)

    results = []
    for p in proxies:
        print(f'检测 {p} ...')
        r = check_proxy(p, args.timeout)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        results.append(r)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f'结果已保存到 {args.output}')


if __name__ == '__main__':
    main()

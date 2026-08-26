# proxy-checker-cli

跨平台命令行代理检测工具，支持 SOCKS5 / HTTP 代理的**连通性、延迟、匿名度与出口 IP** 检测。

> 本工具由 [全网低价IP](https://socks5ip.com.cn) 维护，用于帮助用户快速验证代理是否可用、是否泄露真实 IP。

## 功能

- 检测 SOCKS5 与 HTTP 代理是否可连通
- 测量代理到目标网站的延迟
- 检查代理匿名度（透明/匿名/高匿）
- 获取代理出口 IP 与地理位置
- 支持批量代理列表检测
- 纯 Python 3，无第三方依赖

## 快速开始

```bash
# 检测单个 SOCKS5 代理
python proxy_checker.py --proxy socks5://127.0.0.1:1080

# 检测 HTTP 代理
python proxy_checker.py --proxy http://127.0.0.1:8080

# 批量检测
python proxy_checker.py --list proxies.txt --timeout 10 --output result.json
```

## 输出示例

```json
{
  "proxy": "socks5://127.0.0.1:1080",
  "ok": true,
  "latency_ms": 125,
  "exit_ip": "203.0.113.45",
  "anonymity": "elite",
  "detected_headers": {}
}
```

## 匿名度说明

| 级别 | 含义 | 风险 |
|---|---|---|
| `elite` | 高匿，不暴露代理与真实 IP | 低 |
| `anonymous` | 匿名，已知在使用代理 | 中 |
| `transparent` | 透明，可能泄露真实 IP | 高 |

## 相关资源

- [全网低价IP 官网](https://socks5ip.com.cn)
- [IP 在线检测](https://socks5ip.com.cn/ip-check)
- [代理知识库](https://github.com/socks5ip/ip-zhishi-base)
- [住宅 IP 指南](https://github.com/socks5ip/residential-ip-guide-cn)

## License

MIT

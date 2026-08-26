# proxy-checker-cli

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey.svg)
![Made by](https://img.shields.io/badge/made%20by-%E5%85%A8%E7%BD%91%E4%BD%8E%E4%BB%B7IP-orange.svg)

跨平台命令行代理检测工具，支持 SOCKS5 / HTTP 代理的**连通性、延迟、匿名度与出口 IP** 检测。

> 由 [全网低价IP](https://socks5ip.com.cn) 维护，用于快速验证代理是否可用、是否泄露真实 IP。

## 功能

- 检测 SOCKS5 与 HTTP 代理是否可连通
- 测量代理到目标网站的延迟
- 检查代理匿名度（透明 / 匿名 / 高匿 elite）
- 获取代理出口 IP
- 支持批量代理列表检测，结果导出 JSON
- **纯 Python 3 标准库，零第三方依赖**

## 安装

```bash
pip install proxy-checker-cli
```

或从源码安装：

```bash
git clone https://github.com/socks5ip/proxy-checker-cli.git
cd proxy-checker-cli
pip install .
```

## 使用

安装后可直接用命令 `proxy-checker`：

```bash
# 检测单个 SOCKS5 代理
proxy-checker --proxy socks5://127.0.0.1:1080

# 检测带认证的 HTTP 代理
proxy-checker --proxy http://user:pass@127.0.0.1:8080

# 批量检测（每行一个代理）
proxy-checker --list proxies.txt --output result.json
```

也可直接运行脚本（无需安装）：

```bash
python proxy_checker.py --proxy socks5://127.0.0.1:1080
```

输出示例：

```json
{
  "proxy": "socks5://127.0.0.1:1080",
  "ok": true,
  "latency_ms": 142.3,
  "exit_ip": "203.0.113.45",
  "anonymity": "elite",
  "error": null
}
```

## 典型场景

- **选型前自检**：买代理前先批量测速，挑延迟低、匿名度高的节点。
- **日常巡检**：定时跑 `--list` 检测代理池健康度。
- **匿名度验证**：确认代理没有泄露真实 IP（透明/匿名会暴露 `X-Forwarded-For` 等头）。

## 相关项目

- [proxy-resource-hub](https://github.com/socks5ip/proxy-resource-hub) — 代理IP资源与检测脚本库
- [awesome-proxy-providers](https://github.com/socks5ip/awesome-proxy-providers) — 代理IP服务商精选清单与对比
- [IP 网络知识库](https://github.com/socks5ip/ip-zhishi-base)
- 官网与在线检测：[socks5ip.com.cn](https://socks5ip.com.cn)（[IP 质量检测](https://socks5ip.com.cn/ip-check) · [线路检测](https://socks5ip.com.cn/proxy-check)）

## License

[MIT](LICENSE)

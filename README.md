# 项目定义

基于 Linux 和 libpcap 的网络嗅探器，使用 C++ 捕获和解析数据包，通过浏览器查看网络流量、协议字段和 TCP 会话。

# 快速开始

在 Ubuntu 上安装构建依赖：

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev libcap2-bin
```

在项目根目录编译。安装脚本将抓包辅助程序放入系统目录并授予抓包权限：

```bash
cmake -S . -B build
cmake --build build -j2
sudo bash scripts/install-capture-helper.sh
```

使用普通用户启动服务：

```bash
bash scripts/run.sh
```

浏览器打开 http://127.0.0.1:8080/，选择要监听的网络接口（可先选择 any）并点击 Record 开始抓包。停止服务时在终端按 Ctrl+C。

# 功能实现

- 使用 libpcap 枚举接口、过滤并捕获数据包，支持导出 pcap。
- 解析 IPv4、IPv6、TCP、UDP、ICMP、ICMPv6 ，并支持部分 DNS 和明文 HTTP/1.x 解析，查看字段及对应原始字节。
- 按协议、地址、端口、时间和 TCP 会话筛选，使用时间图查看包数及字节分布。
- 按通信双方的 IP 和端口归组 TCP 会话，尝试关联当前用户的 Linux 进程。短连接可能无法关联到进程。
- 重组当前仍保留的 TCP 数据，分析固定长度和 chunked 等 HTTP 正文；需要捕获并保留连接握手和相关数据，默认保留最多 5000 包或 64 MiB，超限淘汰旧包，数据缺失时分析可能不完整。
- 提供 Wireshark Lua DNS 分析插件，可对导出的 pcap 进行补充分析。

网页界面使用 ECharts、Split.js 和 Chrome DevTools 图标，许可证保存在项目中。
# 项目定义

基于 Linux 和 libpcap 的网络嗅探器，使用 C++ 捕获和解析数据包，通过浏览器查看网络流量、协议字段和 TCP 会话。

# 快速开始

在 Ubuntu 上安装构建依赖：

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev libcap2-bin
```

在项目根目录依次执行以下命令。第一条编译项目，第二条使用 `sudo` 安装抓包辅助程序并授予抓包权限，第三条以普通用户启动网页服务。

```bash
bash scripts/quickstart.sh build
bash scripts/quickstart.sh install
bash scripts/quickstart.sh web
```

浏览器打开 http://127.0.0.1:8080/，选择要监听的网络接口（可先选择 any）并点击 Record 开始抓包。停止服务时在终端按 Ctrl+C。

可选的 eBPF 进程追踪由 Linux 内核在 TCP 建连和接受连接时记录进程信息，即使进程很快退出，也能保留它与连接的关联。需要 Ubuntu 的 `clang` 和 `libbpf-dev` 软件包，以及支持 BTF（内核类型信息）的 Linux 内核，可查看 `/sys/kernel/btf/vmlinux` 是否存在。在项目根目录执行：

```bash
bash scripts/quickstart.sh build -DWIRELENS_TCP_OWNER=ON
events=$(mktemp)
echo "$events"
sudo "$PWD/build/wirelens-tcp-owner" "$PWD/build/tcp_owner.bpf.o" "$(id -u)" > "$events"
```

看到 `TCP owner probe ready` 后，在同一 Linux 环境的另一个终端，用普通用户进入项目根目录并执行 `WIRELENS_TCP_OWNER_EVENTS=/实际输出的文件路径 bash scripts/quickstart.sh web`，然后开始抓包。探针需要特权，网页服务仍以普通用户运行。实验结束后按 Ctrl+C 停止探针，再删除事件文件。

# 功能实现

- 使用 libpcap 枚举接口、过滤并捕获数据包，支持导出 pcap。
- 解析 IPv4、IPv6、TCP、UDP、ICMP、ICMPv6 ，并支持部分 DNS 和明文 HTTP/1.x 解析，查看字段及对应原始字节。
- 按协议、地址、端口、时间和 TCP 会话筛选，使用时间图查看包数及字节分布。
- 按通信双方的 IP 和端口归组 TCP 会话，尝试关联当前用户的 Linux 进程。默认通过 /proc 快照识别进程，可以启用 eBPF 补充短连接归属。
- 重组当前仍保留的 TCP 数据，分析固定长度、分块传输和由服务端关闭连接定界的 HTTP 正文；缺少握手时会尝试从保留的数据推断请求与响应，默认保留最多 5000 包或 64 MiB，超限淘汰旧包，数据缺失时分析可能不完整。
- 提供 Wireshark Lua DNS 分析插件，可对导出的 pcap 进行补充分析。

网页界面使用 ECharts、Split.js 和 Chrome DevTools 图标，许可证保存在项目中。
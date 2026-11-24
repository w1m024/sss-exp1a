# WireLens

基于 Linux 和 libpcap 的网络嗅探器，使用 C++ 捕获和解析数据包，通过浏览器查看网络流量、协议字段和 TCP 会话。

## 快速开始
安装构建依赖：

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev libcap2-bin
```

在项目根目录依次执行以下命令。第一条编译项目，第二条使用 `sudo` 安装抓包辅助程序并授予抓包权限，第三条以普通用户启动网页服务。

```bash
bash scripts/quickstart.sh build
bash scripts/quickstart.sh install
bash scripts/quickstart.sh web
```

在浏览器中打开 <http://127.0.0.1:8080/>。选择要监听的网络接口，然后点击 **Record** 开始抓包。

## 可选的 eBPF 进程追踪

启用 eBPF 后，探针会在 TCP 主动建连和接受连接时记录进程信息，帮助识别短连接关联的进程。即使进程很快退出，仍可用这些记录关联已捕获的 TCP 会话。

### 首次构建

在 Ubuntu 上安装依赖，并检查内核是否提供 BTF（内核类型信息）。

```bash
sudo apt install clang libbpf-dev
ls /sys/kernel/btf/vmlinux
```

确认文件存在后，在项目根目录构建。

```bash
bash scripts/quickstart.sh build -DWIRELENS_TCP_OWNER=ON
```

### 终端 1：启动采集器

用普通用户进入项目根目录。采集器需要通过 `sudo` 加载探针，并将连接事件写入临时文件。

```bash
events=$(mktemp)
echo "$events"
sudo ./build/wirelens-tcp-owner ./build/tcp_owner.bpf.o "$(id -u)" > "$events"
```

看到 `TCP owner probe ready` 后，保持采集器运行。

### 终端 2：启动网页服务

在同一 Linux 环境中，用普通用户进入项目根目录。将下方的 `/tmp/示例路径` 换成终端 1 打印的完整路径。

```bash
WIRELENS_TCP_OWNER_EVENTS="/tmp/示例路径" bash scripts/quickstart.sh web
```

打开网页并开始抓包。实验结束后，先在终端 2 按 `Ctrl+C` 停止网页服务，再在终端 1 按 `Ctrl+C` 停止采集器，并执行 `rm -- "$events"` 清理临时文件。

## 功能实现

- 使用 libpcap 枚举接口、过滤并捕获数据包，支持导出 pcap。
- 解析 IPv4、IPv6、TCP、UDP、ICMP、ICMPv6 ，并支持部分 DNS 和明文 HTTP/1.x 解析，查看字段及对应原始字节。
- 按协议、地址、端口、时间和 TCP 会话筛选，使用时间图查看包数及字节分布。
- 按通信双方的 IP 和端口归组 TCP 会话，尝试关联当前用户的 Linux 进程。默认通过 /proc 快照识别进程，可以启用 eBPF 补充短连接归属。
- 重组当前仍保留的 TCP 数据，分析固定长度、分块传输和由服务端关闭连接定界的 HTTP 正文；缺少握手时会尝试从保留的数据推断请求与响应，默认保留最多 5000 包或 64 MiB，超限淘汰旧包，数据缺失时分析可能不完整。
- 提供 Wireshark Lua DNS 分析插件，可对导出的 pcap 进行补充分析。

## 第三方组件

| 组件 | 用途 | 许可证与声明 |
| --- | --- | --- |
| Apache ECharts | 绘制流量时间图 | [Apache-2.0](vendor/licenses/echarts.LICENSE) · [NOTICE](vendor/licenses/echarts.NOTICE) |
| Split.js | 调整页面分栏 | [MIT](vendor/licenses/splitjs.LICENSE) |
| Chrome DevTools 图标 | 网页工具栏图标 | [BSD-3-Clause](vendor/licenses/devtools.LICENSE) |
| cpp-httplib | 提供本地 HTTP 服务 | [MIT](vendor/cpp-httplib.LICENSE) |

随源码分发的组件来源与版本记录见[前端组件](vendor/ui-upstream.json)和[后端组件](vendor/upstream.json)。

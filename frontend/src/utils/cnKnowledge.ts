/**
 * 面向中文计算机网络初学者的协议字段百科库、动态报文解说器与教科书 32 位首部位图构造器。
 * 将真实捕获的原始字节直接映射为《计算机网络（自顶向下/谢希仁版）》中的经典概念与图形结构。
 */
import type { PacketDetail, PacketSummary, StreamSummary } from '../types'

export interface FieldKnowledge {
  key: string
  zhTitle: string
  enName: string
  osiLayer: number
  plainExplain: string
  examTip?: string
  securityTip?: string
}

export const FIELD_KNOWLEDGE_DB: Record<string, FieldKnowledge> = {
  // L1 Frame
  'frame.number': {
    key: 'frame.number',
    zhTitle: '帧捕获序号',
    enName: 'Frame Number',
    osiLayer: 1,
    plainExplain: '嗅探器按时间先后为每个抓到的原始数据帧分配的递增编号，仅用于分析定位，不在网络上传输。',
  },
  'frame.len': {
    key: 'frame.len',
    zhTitle: '链路层帧总长度',
    enName: 'Frame Length on Wire',
    osiLayer: 1,
    plainExplain: '该帧在物理链路上实际占用的字节数（以太网标准最小 60/64 字节，MTU 通常为 1500 字节，含 14 字节以太网头即 1514 字节）。',
    examTip: '以太网最小帧长 64 字节（含 4 字节 FCS）是为了保证 CSMA/CD 冲突检测有效。',
  },
  'frame.protocols': {
    key: 'frame.protocols',
    zhTitle: '协议封装栈',
    enName: 'Protocol Stack',
    osiLayer: 1,
    plainExplain: '展示该数据包从底层到高层的完整协议嵌套关系（如 eth:ip:tcp:http），体现 OSI 分层封装思想。',
  },

  // L2 Ethernet & ARP
  'eth.dst': {
    key: 'eth.dst',
    zhTitle: '目的 MAC 地址',
    enName: 'Destination MAC Address',
    osiLayer: 2,
    plainExplain: '下一跳设备（同局域网主机或默认网关路由器）的 48 位硬件网卡地址。ff:ff:ff:ff:ff:ff 表示局域网广播。',
    examTip: '跨网段通信时，IP 目的地址始终是最终目标主机，而每经过一个路由器，MAC 地址都会逐跳改变！',
  },
  'eth.src': {
    key: 'eth.src',
    zhTitle: '源 MAC 地址',
    enName: 'Source MAC Address',
    osiLayer: 2,
    plainExplain: '发送当前以太网帧的网卡 48 位硬件地址，前 24 位（OUI）标识网卡厂商（如 Intel、VMware、Huawei）。',
  },
  'eth.type': {
    key: 'eth.type',
    zhTitle: '以太网类型 (EtherType)',
    enName: 'EtherType',
    osiLayer: 2,
    plainExplain: '指明以太网帧载荷中封装的上层协议类型：0x0800 = IPv4，0x0806 = ARP，0x86DD = IPv6，0x8100 = 802.1Q VLAN。',
    examTip: '解封装时，网卡/内核就是靠 EtherType 决定把载荷交给 IPv4、IPv6 还是 ARP 模块处理。',
  },
  'arp.opcode': {
    key: 'arp.opcode',
    zhTitle: 'ARP 操作码',
    enName: 'ARP Opcode',
    osiLayer: 2,
    plainExplain: '1 表示 ARP 请求（广播询问某 IP 对应的 MAC），2 表示 ARP 响应（单播/免费 ARP 宣告某 IP 的 MAC）。',
    securityTip: 'ARP 协议本身无身份认证！攻击者伪造 Opcode=2 的 ARP 响应即可实施 ARP 欺骗/中间人攻击（MITM）。',
  },
  'arp.src.hw_mac': {
    key: 'arp.src.hw_mac',
    zhTitle: '发送方 MAC 地址',
    enName: 'Sender Hardware Address',
    osiLayer: 2,
    plainExplain: '发出该 ARP 报文的主机声明的硬件 MAC 地址。',
  },
  'arp.src.proto_ipv4': {
    key: 'arp.src.proto_ipv4',
    zhTitle: '发送方 IP 地址',
    enName: 'Sender Protocol Address',
    osiLayer: 2,
    plainExplain: '发出该 ARP 报文的主机声明的 IPv4 地址，接收方会据此更新自己的 ARP 缓存表（IP → MAC）。',
    securityTip: '当同一个网关 IP 突然对应了一个陌生的新 MAC，WirePulse 安全雷达会立即报 CRITICAL 级 ARP 欺骗告警。',
  },
  'arp.dst.proto_ipv4': {
    key: 'arp.dst.proto_ipv4',
    zhTitle: '目标 IP 地址',
    enName: 'Target Protocol Address',
    osiLayer: 2,
    plainExplain: 'ARP 请求想要查询其 MAC 地址的目标 IPv4 地址。',
  },

  // L3 IPv4 & IPv6 & ICMP
  'ip.version': {
    key: 'ip.version',
    zhTitle: 'IP 协议版本',
    enName: 'IP Version',
    osiLayer: 3,
    plainExplain: '4 位字段，值为 4 代表 IPv4（32 位地址），值为 6 代表 IPv6（128 位地址）。',
  },
  'ip.hdr_len': {
    key: 'ip.hdr_len',
    zhTitle: 'IPv4 首部长度 (IHL)',
    enName: 'Internet Header Length',
    osiLayer: 3,
    plainExplain: '4 位字段，单位是「4 字节（32 位字）」。常见值为 5，表示 5 × 4 = 20 字节标准首部（无可选字段）；最大值为 15（60 字节）。',
    examTip: '高频选择题：IHL 的单位是 4 字节，而 IPv4 总长度（Total Length）的单位是 1 字节，片偏移的单位是 8 字节！',
  },
  'ip.dsfield': {
    key: 'ip.dsfield',
    zhTitle: '区分服务 (DSCP / ECN)',
    enName: 'Differentiated Services / TOS',
    osiLayer: 3,
    plainExplain: '高 6 位 DSCP 用于 QoS 流量优先级标记（如语音/视频优先），低 2 位 ECN 用于显式拥塞通知。',
  },
  'ip.len': {
    key: 'ip.len',
    zhTitle: 'IP 数据报总长度',
    enName: 'Total Length',
    osiLayer: 3,
    plainExplain: '16 位字段，表示 IP 首部 + IP 载荷的总字节数（不含以太网帧头），理论最大 65535 字节。',
  },
  'ip.id': {
    key: 'ip.id',
    zhTitle: '标识 (Identification)',
    enName: 'Identification',
    osiLayer: 3,
    plainExplain: '16 位计数器，当一个大 IP 包超过链路 MTU 被拆成多个分片时，同一原包的所有分片共享相同的 Identification 以便重组。',
  },
  'ip.flags': {
    key: 'ip.flags',
    zhTitle: 'IP 分片标志与片偏移',
    enName: 'Flags (DF/MF) & Fragment Offset',
    osiLayer: 3,
    plainExplain: 'DF=1（Don\'t Fragment）禁止路由器分片（用于路径 MTU 发现）；MF=1 表示后面还有更多分片；片偏移以 8 字节为单位指出该分片在原数据报中的位置。',
    examTip: '片偏移单位 = 8 字节，因此除最后一个分片外，每个分片的数据长度必须是 8 的整数倍。',
  },
  'ip.ttl': {
    key: 'ip.ttl',
    zhTitle: '生存时间 (TTL)',
    enName: 'Time To Live',
    osiLayer: 3,
    plainExplain: '防止数据包在路由环路中无限兜圈！每经过一台路由器 TTL 减 1，减至 0 时路由器丢弃该包并回送 ICMP 超时报文。',
    examTip: 'Traceroute 工具正是利用递增 TTL=1,2,3... 触发沿途路由器回送 ICMP Time Exceeded 来探测整条路由路径！常见初始 TTL：Linux/macOS=64，Windows=128，网络设备=255。',
  },
  'ip.proto': {
    key: 'ip.proto',
    zhTitle: '上层协议号 (Protocol)',
    enName: 'IP Protocol Number',
    osiLayer: 3,
    plainExplain: '8 位字段，告诉网络层把 IP 载荷交给哪个传输层协议：1=ICMP，6=TCP，17=UDP，58=ICMPv6。',
  },
  'ip.checksum': {
    key: 'ip.checksum',
    zhTitle: '首部校验和',
    enName: 'Header Checksum',
    osiLayer: 3,
    plainExplain: '仅对 IPv4 首部进行 16 位二进制反码求和校验（不校验数据部分）。每跳路由器修改 TTL 后都需要重新计算。',
    examTip: '抓包本机发出的包时常看到校验和「incorrect / offload」，这是现代网卡硬件校验和卸载（Checksum Offload）的正常现象：内核抓包点在网卡硬件计算前。',
  },
  'ip.src': {
    key: 'ip.src',
    zhTitle: '源 IP 地址',
    enName: 'Source IP Address',
    osiLayer: 3,
    plainExplain: '32 位逻辑地址，标识发送该数据包的主机（或经过 NAT 转换后的出口路由器）。',
  },
  'ip.dst': {
    key: 'ip.dst',
    zhTitle: '目的 IP 地址',
    enName: 'Destination IP Address',
    osiLayer: 3,
    plainExplain: '32 位逻辑地址，路由器依据目的 IP 查找路由表（最长前缀匹配）决定下一跳转发方向。',
  },
  'icmp.type': {
    key: 'icmp.type',
    zhTitle: 'ICMP 报文类型',
    enName: 'ICMP Type',
    osiLayer: 3,
    plainExplain: '用于网络诊断与差错报告：Type 8 = Ping 请求（Echo Request），Type 0 = Ping 应答（Echo Reply），Type 3 = 目的不可达，Type 11 = TTL 超时。',
  },

  // L4 TCP & UDP
  'tcp.srcport': {
    key: 'tcp.srcport',
    zhTitle: 'TCP 源端口',
    enName: 'TCP Source Port',
    osiLayer: 4,
    plainExplain: '16 位端口号（0–65535），用来区分同一台主机上不同的应用程序进程。客户端通常随机分配 49152–65535 临时端口。',
    examTip: '四元组 (源IP, 源端口, 目的IP, 目的端口) 唯一标识一条 TCP 连接。',
  },
  'tcp.dstport': {
    key: 'tcp.dstport',
    zhTitle: 'TCP 目的端口',
    enName: 'TCP Destination Port',
    osiLayer: 4,
    plainExplain: '目标服务器监听的服务端口（常见知名端口：21=FTP、22=SSH、80=HTTP、443=HTTPS、3306=MySQL），但实际服务也可能运行在非标端口。',
  },
  'tcp.seq': {
    key: 'tcp.seq',
    zhTitle: 'TCP 序列号 (Seq)',
    enName: 'Sequence Number',
    osiLayer: 4,
    plainExplain: 'TCP 是面向字节流的可靠协议，Seq 标明本报文段第一个数据字节在字节流中的编号。工具通常显示从 0 开始的相对序号便于阅读（真实原始 ISN 是随机数以防劫持）。',
    examTip: '若本次发送 Seq=1、载荷 Len=132，则下一包期望 Seq=133；SYN 和 FIN 标志位虽不带数据，但也各自消耗 1 个序号！',
  },
  'tcp.ack': {
    key: 'tcp.ack',
    zhTitle: 'TCP 确认号 (Ack)',
    enName: 'Acknowledgment Number',
    osiLayer: 4,
    plainExplain: '表示「Ack 之前的所有字节我已按序收齐，期望对方下一个发来的字节编号是 Ack」（累积确认机制）。仅当 ACK 标志位为 1 时有效。',
  },
  'tcp.hdr_len': {
    key: 'tcp.hdr_len',
    zhTitle: 'TCP 数据偏移 / 首部长度',
    enName: 'TCP Data Offset',
    osiLayer: 4,
    plainExplain: '4 位字段，单位为 4 字节。无选项时为 5（20 字节），携带 MSS/时间戳/窗口扩大等选项时常见为 32 或 40 字节（最大 60 字节）。',
  },
  'tcp.flags': {
    key: 'tcp.flags',
    zhTitle: 'TCP 控制标志位',
    enName: 'TCP Control Flags',
    osiLayer: 4,
    plainExplain: '控制连接状态的核心开关：SYN（发起连接）、ACK（确认有效）、FIN（优雅关闭）、RST（异常强制重置）、PSH（催促立即交付应用层）、URG（紧急数据）。',
    securityTip: 'Nmap 端口扫描常构造非常规标志组合：仅 SYN（半开扫描）、FIN+PSH+URG（XMAS 圣诞树扫描）、全 0（NULL 扫描）。',
  },
  'tcp.flags.syn': {
    key: 'tcp.flags.syn',
    zhTitle: 'SYN 同步标志',
    enName: 'TCP SYN Flag',
    osiLayer: 4,
    plainExplain: 'SYN=1, ACK=0 表示三次握手第 1 步（客户端请求建连）；SYN=1, ACK=1 表示第 2 步（服务端同意并同步序号）。',
    securityTip: '短时间内大量发 SYN 却不回 ACK 会耗尽服务端半连接队列，构成 SYN Flood 拒绝服务攻击。',
  },
  'tcp.flags.rst': {
    key: 'tcp.flags.rst',
    zhTitle: 'RST 连接重置标志',
    enName: 'TCP Reset Flag',
    osiLayer: 4,
    plainExplain: '表明连接遇到严重异常或目标端口未开放，要求立即强行终止该 TCP 连接（无需四次挥手）。',
  },
  'tcp.window_size': {
    key: 'tcp.window_size',
    zhTitle: '接收窗口大小 (Window)',
    enName: 'TCP Receive Window',
    osiLayer: 4,
    plainExplain: '实现「流量控制（滑动窗口）」的关键字段！接收方借此通告自己接收缓冲区还能装下多少字节，防止发送方发太快导致溢出。',
    examTip: 'Window=0（零窗口）意味着接收方缓冲区已满，发送方必须暂停发送并定期发送窗口探测包。',
  },
  'tcp.checksum': {
    key: 'tcp.checksum',
    zhTitle: 'TCP 校验和',
    enName: 'TCP Checksum',
    osiLayer: 4,
    plainExplain: '覆盖「IP 伪首部 + TCP 首部 + TCP 数据」，确保报文在传输中未发生比特翻转且送到了正确的 IP 地址。',
  },
  'tcp.options': {
    key: 'tcp.options',
    zhTitle: 'TCP 选项字段',
    enName: 'TCP Options',
    osiLayer: 4,
    plainExplain: '协商高级传输特性：MSS（最大报文段长度，常为 1460B）、Window Scale（窗口扩大因子突破 64KB 限制）、SACK（选择性确认精准重传）、Timestamps（精确测算 RTT）。',
  },
  'udp.srcport': {
    key: 'udp.srcport',
    zhTitle: 'UDP 源端口',
    enName: 'UDP Source Port',
    osiLayer: 4,
    plainExplain: 'UDP 是无连接、不可靠但极低延迟的传输协议，首部仅固定 8 字节，广泛用于 DNS、DHCP、QUIC (HTTP/3) 与音视频流。',
  },
  'udp.dstport': {
    key: 'udp.dstport',
    zhTitle: 'UDP 目的端口',
    enName: 'UDP Destination Port',
    osiLayer: 4,
    plainExplain: '接收方 UDP 服务端口（如 53=DNS、67/68=DHCP、123=NTP、443=QUIC）。',
  },
  'udp.length': {
    key: 'udp.length',
    zhTitle: 'UDP 数据报长度',
    enName: 'UDP Length',
    osiLayer: 4,
    plainExplain: '8 字节 UDP 首部 + 应用层载荷的总字节数，最小值为 8。',
  },

  // L6-L7 Application
  'dpi.method': {
    key: 'dpi.method',
    zhTitle: '应用层 DPI 识别依据',
    enName: 'Deep Packet Inspection Method',
    osiLayer: 7,
    plainExplain: '展示 WirePulse 是如何识别出该应用层协议的：优先通过载荷魔数与语法特征识别（Port-Agnostic DPI），即便服务跑在非标端口（如 8888/2222）也能精准识别！',
  },
  'http.request.method': {
    key: 'http.request.method',
    zhTitle: 'HTTP 请求方法',
    enName: 'HTTP Request Method',
    osiLayer: 7,
    plainExplain: '定义对服务器资源的操作语义：GET（获取资源）、POST（提交数据）、PUT（更新）、DELETE（删除）。HTTP/1.x 是人类可读的纯文本协议。',
    securityTip: '未加密的 HTTP 流量中，URL 参数、表单密码、Cookie 和 Authorization 头都会以明文暴露在链路上！',
  },
  'http.request.uri': {
    key: 'http.request.uri',
    zhTitle: 'HTTP 请求路径与查询参数',
    enName: 'HTTP Request URI',
    osiLayer: 7,
    plainExplain: '指定要访问的服务器路径及 ? 后的查询参数。',
    securityTip: '攻击者常在 URI 参数中注入 SQL 语句（如 \' OR 1=1）、<script> XSS 脚本或 ../../etc/passwd 路径穿越载荷。',
  },
  'http.response.code': {
    key: 'http.response.code',
    zhTitle: 'HTTP 响应状态码',
    enName: 'HTTP Status Code',
    osiLayer: 7,
    plainExplain: '2xx 成功（200 OK）、3xx 重定向（301/302）、4xx 客户端错误（401 未认证、403 禁止、404 未找到）、5xx 服务端错误（500/502）。',
  },
  'http.authorization': {
    key: 'http.authorization',
    zhTitle: 'HTTP 认证请求头',
    enName: 'HTTP Authorization Header',
    osiLayer: 7,
    plainExplain: '携带客户端身份凭证（如 Basic Base64 编码或 Bearer JWT 令牌）。',
    securityTip: '⚠️ Base64 是编码而非加密！任何嗅探器可直接解码出明文账号密码，必须配合 HTTPS/TLS 使用。',
  },
  'dns.id': {
    key: 'dns.id',
    zhTitle: 'DNS 事务 ID',
    enName: 'DNS Transaction ID',
    osiLayer: 7,
    plainExplain: '16 位随机编号，用于把异步返回的 DNS 响应报文与之前发出的 DNS 查询一一配对。',
  },
  'dns.qry.name': {
    key: 'dns.qry.name',
    zhTitle: 'DNS 查询域名',
    enName: 'DNS Query Name',
    osiLayer: 7,
    plainExplain: '客户端希望解析成 IP 地址的域名（如 github.com）。DNS 报文中以「长度字节+标签」序列编码并支持指针压缩节省空间。',
    securityTip: '如果发现超长且高随机熵的子域名查询（如 a9f4k2m8...evil.net），极可能是木马正在利用 DNS 隧道偷偷外传数据！',
  },
  'dns.a': {
    key: 'dns.a',
    zhTitle: 'DNS A 记录（IPv4 解析结果）',
    enName: 'DNS A Record',
    osiLayer: 7,
    plainExplain: 'DNS 服务器返回的域名对应的 32 位 IPv4 地址（AAAA 记录则对应 128 位 IPv6 地址，CNAME 为别名）。',
  },
  'tls.handshake.sni': {
    key: 'tls.handshake.sni',
    zhTitle: 'TLS 服务器名称指示 (SNI)',
    enName: 'Server Name Indication',
    osiLayer: 6,
    plainExplain: '在 TLS ClientHello 握手阶段明文发送目标域名，使同一 IP 上的服务器能返回对应域名的数字证书。',
    securityTip: '即使 HTTPS 加密了正文，嗅探器仍可从 ClientHello 的 SNI 字段看出用户正在访问哪个网站（除非启用 ECH 加密客户端问候）。',
  },
  'tls.ja3': {
    key: 'tls.ja3',
    zhTitle: 'JA3 TLS 客户端指纹',
    enName: 'JA3 Fingerprint',
    osiLayer: 6,
    plainExplain: '将 ClientHello 中的 TLS 版本、密码套件列表、扩展、椭圆曲线组合后做 MD5 哈希，无需解密即可识别发起连接的客户端类型（Chrome / curl / Python / 恶意木马）。',
  },
  'tls.record.version': {
    key: 'tls.record.version',
    zhTitle: 'TLS 协议版本',
    enName: 'TLS Protocol Version',
    osiLayer: 6,
    plainExplain: '协商加密通信使用的安全传输层标准。现代互联网要求使用 TLS 1.2 或 TLS 1.3，TLS 1.0/1.1 已被 RFC 8996 正式废弃。',
  },
  'quic.version': {
    key: 'quic.version',
    zhTitle: 'QUIC 协议版本 (HTTP/3 基石)',
    enName: 'QUIC Version',
    osiLayer: 7,
    plainExplain: 'Google 提出并经 IETF RFC 9000 标准化的下一代传输协议：基于 UDP 实现可靠传输、内置 TLS 1.3 加密、消除队头阻塞并支持 0-RTT 快速建连。',
  },
}

export function lookupFieldKnowledge(fieldKey: string, label?: string): FieldKnowledge | null {
  if (!fieldKey) return null
  const k = fieldKey.toLowerCase()
  if (FIELD_KNOWLEDGE_DB[k]) return FIELD_KNOWLEDGE_DB[k]
  // Prefix fallback
  for (const dbKey of Object.keys(FIELD_KNOWLEDGE_DB)) {
    if (k.startsWith(dbKey + '.')) return FIELD_KNOWLEDGE_DB[dbKey]
  }
  if (k.startsWith('http.')) {
    return {
      key: k,
      zhTitle: `HTTP 头部字段 (${fieldKey.replace('http.', '')})`,
      enName: label || fieldKey,
      osiLayer: 7,
      plainExplain: 'HTTP 请求或响应中的元数据键值对（Header），用于传递主机名、内容格式、浏览器标识或缓存策略。',
    }
  }
  if (k.startsWith('tls.')) {
    return {
      key: k,
      zhTitle: 'TLS 安全传输层字段',
      enName: label || fieldKey,
      osiLayer: 6,
      plainExplain: '用于在客户端与服务器之间协商加密算法、校验数字证书并保护应用层数据机密性与完整性。',
    }
  }
  if (k.startsWith('dns.')) {
    return {
      key: k,
      zhTitle: 'DNS 域名系统字段',
      enName: label || fieldKey,
      osiLayer: 7,
      plainExplain: 'DNS 协议（RFC 1035）字段，负责互联网域名与 IP 地址之间的分布式映射解析。',
    }
  }
  if (k.startsWith('dhcp.')) {
    return {
      key: k,
      zhTitle: 'DHCP 动态地址分配字段',
      enName: label || fieldKey,
      osiLayer: 7,
      plainExplain: '主机会通过 Discover → Offer → Request → ACK 四步 DHCP 交互自动获取 IP、子网掩码、默认网关与 DNS 服务器。',
    }
  }
  return null
}

/**
 * 为任意真实捕获的数据包生成「本科生一眼就能看懂的中文大白话故事」
 */
export interface PacketNarration {
  headline: string
  story: string
  keyConcept: string
  takeaways: string[]
  securityNote?: string
}

export function narratePacketZh(detail: PacketDetail): PacketNarration {
  const s = detail.summary
  const proto = s.protocol.toUpperCase()
  const srcEp = s.srcPort ? `${s.src}:${s.srcPort}` : s.src
  const dstEp = s.dstPort ? `${s.dst}:${s.dstPort}` : s.dst
  const takeaways: string[] = []
  let securityNote: string | undefined

  if (s.alertSeverity) {
    securityNote = `安全 IDS 已标记该帧 [${s.alertSeverity}]：${s.alertRules.join('、')}，建议前往「安全雷达」查看取证详情。`
  }

  if (proto === 'ARP') {
    const isReq = s.info.includes('Who has')
    return {
      headline: isReq ? '局域网广播：ARP 地址解析请求' : '局域网响应：ARP 地址宣告',
      story: isReq
        ? `主机 ${s.src} 想要通信，但只知道对方的 IP 地址，不知道对应的物理网卡 MAC 地址，于是向局域网所有设备广播「${s.info}」。`
        : `设备宣告了 IP 与 MAC 的映射关系：「${s.info}」。收到该包的设备会将该映射写入本地 ARP 缓存表。`,
      keyConcept: 'ARP 工作在 L2/L3 交界处，解决「已知 IP 找 MAC」的问题，仅在同一个局域网广播域内有效。',
      takeaways: [
        '以太网数据帧必须填写 48 位目的 MAC 才能在局域网发送',
        'ARP 请求使用全 F 广播（ff:ff:ff:ff:ff:ff），ARP 响应通常为单播',
        'ARP 无鉴权机制，是局域网中间人欺骗的经典入口',
      ],
      securityNote,
    }
  }

  if (proto === 'DNS' || proto === 'MDNS') {
    const isResp = s.info.includes('response')
    return {
      headline: isResp ? 'DNS 域名解析响应（拿到了 IP 地址）' : 'DNS 域名解析查询（把域名翻译成 IP）',
      story: isResp
        ? `DNS 服务器 ${srcEp} 回复了主机 ${dstEp} 的查询：${s.info}。主机拿到 IP 后就能发起真正的 TCP/UDP 连接。`
        : `主机 ${srcEp} 向 DNS 服务器 ${dstEp} 发起查询（${s.info}），请求把人类可读的域名翻译为机器可路由的 IP 地址。`,
      keyConcept: 'DNS 是互联网的「电话簿」，默认使用轻量级无连接 UDP 53 端口，单次往返即可完成解析。',
      takeaways: [
        '同一对查询与响应通过 16 位 Transaction ID 精准匹配',
        'A 记录返回 IPv4，AAAA 返回 IPv6，TXT 可携带文本（常被用于验证或 DNS 隧道）',
        s.dpiMethod ? `识别方式：${s.dpiMethod}` : '采用 RFC 1035 指针压缩编码减小报文体积',
      ],
      securityNote,
    }
  }

  if (proto === 'DHCP') {
    return {
      headline: `DHCP 自动联网配置（${s.info.split(' ')[1] || '交互'}）`,
      story: `设备正在与局域网 DHCP 服务器交互（${s.info}），通过著名的 DORA 四步曲（Discover → Offer → Request → ACK）自动租用 IP 地址、网关和 DNS。`,
      keyConcept: '新设备刚连上 Wi-Fi/网线时还没有 IP，因此 DHCP 请求使用源 IP 0.0.0.0 与广播目的 255.255.255.255（UDP 68→67）。',
      takeaways: [
        '识别特征：UDP 载荷偏移 236 字节处的魔数 0x63825363',
        '租期（Lease Time）到期前客户端会自动续租',
      ],
      securityNote,
    }
  }

  if (proto === 'HTTP' || proto === 'HTTP2') {
    const isResp = s.info.startsWith('HTTP/')
    return {
      headline: isResp ? `HTTP 应用层响应（${s.info.slice(0, 28)}）` : `HTTP 明文请求（${s.info.split(' ').slice(0, 2).join(' ')}）`,
      story: isResp
        ? `Web 服务器 ${srcEp} 向客户端 ${dstEp} 返回了明文 HTTP 响应（${s.info}），包含状态码、响应头与正文数据。`
        : `客户端 ${srcEp} 向服务器 ${dstEp} 发送了一条明文 HTTP 请求（${s.info}）。${s.dstPort !== 80 ? `注意它运行在非标准端口 ${s.dstPort}，WirePulse 通过 DPI 语法特征而非端口号精准识别了它！` : ''}`,
      keyConcept: 'HTTP 工作在 OSI 第 7 层（应用层），底层依赖 TCP 可靠字节流传输。请求头与正文之间以空行 \\r\\n\\r\\n 分隔。',
      takeaways: [
        `载荷识别依据：${s.dpiMethod || 'HTTP/1.x 语法特征'}`,
        '明文 HTTP 报文在 Hex/ASCII 视图中可以直接读出全部请求路径、Header 与表单内容',
        '若该流包含多轮交互，可点击「追踪流」查看完整拼接后的网页请求与响应',
      ],
      securityNote,
    }
  }

  if (proto.startsWith('TLS') || proto.startsWith('SSL')) {
    const isCH = s.info.includes('Client Hello')
    const isSH = s.info.includes('Server Hello')
    return {
      headline: isCH
        ? `${proto} 加密握手第 1 步：Client Hello`
        : isSH
          ? `${proto} 加密握手第 2 步：Server Hello`
          : `${proto} 安全加密通信报文`,
      story: isCH
        ? `客户端 ${srcEp} 正在向 ${dstEp} 发起 HTTPS/TLS 加密握手（${s.info}）：告知服务器自己支持的加密套件、TLS 版本，并通过 SNI 扩展明文指明目标域名。`
        : isSH
          ? `服务器 ${srcEp} 回应加密握手（${s.info}）：敲定了双方共同使用的加密算法套件，并即将交换公钥/证书建立会话密钥。`
          : `客户端与服务器之间正在传输 ${proto} 记录（${s.info}）。由于已完成密钥协商，应用层业务数据已变成高强度密文，嗅探器无法直接窥探内容。`,
      keyConcept: 'TLS 位于 TCP 与 HTTP 之间（OSI 表示层/会话层），通过非对称加密协商密钥 + 数字证书验真 + 对称加密高效传输数据。',
      takeaways: [
        'ClientHello 中的 SNI 和密码套件列表以明文发送，可据此计算 JA3 客户端指纹',
        '想在合法调试中解密自己抓到的 HTTPS？只需在「WS 扩展」加载 SSLKEYLOGFILE 密钥日志',
      ],
      securityNote,
    }
  }

  if (proto === 'QUIC') {
    return {
      headline: 'QUIC (HTTP/3) 新一代 UDP 加密传输报文',
      story: `主机 ${srcEp} 与 ${dstEp} 正在使用基于 UDP 的 QUIC 协议通信（${s.info}）。它将传统「TCP 握手 + TLS 握手」合二为一，大幅降低首包延迟。`,
      keyConcept: 'QUIC 在用户态基于 UDP 重写了可靠传输与拥塞控制，并使用 Connection ID 替代 IP 四元组，切换 Wi-Fi/5G 不断线！',
      takeaways: [
        '工作在 UDP 443 端口，通过 RFC 9000 长包头特征被 DPI 识别',
        '多路复用流彼此独立，彻底解决 TCP 的队头阻塞（Head-of-Line Blocking）',
      ],
      securityNote,
    }
  }

  if (proto === 'ICMP' || proto === 'ICMPV6') {
    return {
      headline: `${proto} 网络控制与连通性诊断报文`,
      story: `主机 ${srcEp} 向 ${dstEp} 发送了 ${proto} 控制报文（${s.info}），常见于 ping 连通性测试、traceroute 路径追踪或 IPv6 邻居发现（NDP）。`,
      keyConcept: 'ICMP 直接封装在 IP 报文内（不经过 TCP/UDP），属于 L3 网络层的「随行医生」。',
      takeaways: [
        'Echo Request (Type 8) 与 Echo Reply (Type 0) 的时间差即为 Ping 往返时延 RTT',
        'IPv6 取消了 ARP，改用 ICMPv6 的邻居请求/通告（NS/NA）解析链路层 MAC',
      ],
      securityNote,
    }
  }

  if (proto === 'TCP') {
    const f = s.tcpFlags
    const isSyn = f.includes('SYN') && !f.includes('ACK')
    const isSynAck = f.includes('SYN') && f.includes('ACK')
    const isFin = f.includes('FIN')
    const isRst = f.includes('RST')
    const isRetr = s.tcpExpert.some((e) => e.includes('Retrans'))

    let headline = `TCP 传输控制报文 [${f}]`
    let story = `主机 ${srcEp} 向 ${dstEp} 发送了一个 TCP 报文段（${s.info}）。`
    if (isSyn) {
      headline = 'TCP 三次握手第 1 步（SYN 建连请求）'
      story = `客户端 ${srcEp} 主动向服务器 ${dstEp} 发起 TCP 连接请求（SYN=1），同步初始序列号并协商 MSS 与窗口参数。`
    } else if (isSynAck) {
      headline = 'TCP 三次握手第 2 步（SYN+ACK 同意建连）'
      story = `服务器 ${srcEp} 端口开放并同意建连！它在确认客户端序号（ACK）的同时，也向客户端同步了自己的初始序列号（SYN）。`
    } else if (isRst) {
      headline = 'TCP 连接强制重置（RST）'
      story = `${srcEp} 向 ${dstEp} 发送了 RST 重置包：通常是因为目标端口未开启服务、防火墙拦截或应用异常断开。`
    } else if (isFin) {
      headline = 'TCP 四次挥手（FIN 优雅断开连接）'
      story = `${srcEp} 表示自己已经没有更多数据要发送，请求优雅关闭这个方向的 TCP 数据流（FIN 标志消耗 1 个序号）。`
    } else if (isRetr) {
      headline = 'TCP 超时/快速重传（可靠传输保障！）'
      story = `发送方 ${srcEp} 重新发送了之前已经传过的字节区间！这正是 TCP 在不可靠 IP 网络上实现「可靠字节流」的核心机制。`
    } else if (f === 'ACK') {
      headline = 'TCP 纯确认报文（ACK）'
      story = `${srcEp} 告知 ${dstEp}「我已按序收齐确认号之前的数据」，同时通告最新的接收滑动窗口大小。`
    }

    return {
      headline,
      story,
      keyConcept: 'TCP 提供面向连接、按序到达、无差错、不丢失的字节流服务，核心由「三次握手 + 序号/确认 + 滑动窗口 + 拥塞控制」构成。',
      takeaways: [
        'SYN 与 FIN 虽然载荷为 0 字节，但均消耗 1 个序列号',
        s.streamId !== null ? `该包属于 TCP 流 #${s.streamId}，可切到「流与时序」查看完整握手与交互动画` : '点击下方 32 位首部位图可逐字段查看每个比特的含义',
      ],
      securityNote,
    }
  }

  return {
    headline: `${proto} 网络数据包（OSI 第 ${s.osiLayer} 层）`,
    story: `由 ${srcEp} 发往 ${dstEp}，总长 ${s.length} 字节。摘要：${s.info}。`,
    keyConcept: `该数据包自下而上经过了 ${s.protocols.map((p) => p.toUpperCase()).join(' → ')} 逐层封装。`,
    takeaways: [
      `完整协议栈：${s.protocols.join(' : ')}`,
      s.dpiMethod ? `应用层识别：${s.dpiMethod}` : '点击下方不同层次可查看各层真实首部结构',
    ],
    securityNote,
  }
}

/**
 * 教科书经典 32 位首部位图数据结构（实时填入当前抓包数值！）
 */
export interface HeaderBitCell {
  id: string
  fieldKey: string
  zhName: string
  enShort: string
  bitSpan: number // 占 32 位行中的列数 (1..32)
  valueText: string
  rawHex: string
  rawBin: string
  byteOffset: number
  byteLength: number
  highlightTone?: 'cyan' | 'emerald' | 'violet' | 'amber' | 'rose' | 'slate'
}

export interface HeaderDiagramSpec {
  protocol: string
  titleZh: string
  subtitle: string
  osiLayer: number
  totalBytes: number
  rows: HeaderBitCell[][] // 每行 bitSpan 之和 = 32
}

function hexToBytes(hex: string): Uint8Array {
  const len = Math.floor(hex.length / 2)
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function sliceHex(bytes: Uint8Array, off: number, len: number): string {
  const end = Math.min(bytes.length, off + len)
  const parts: string[] = []
  for (let i = off; i < end; i++) parts.push(bytes[i].toString(16).padStart(2, '0'))
  return parts.join(' ')
}

function toBin(val: number, bits: number): string {
  return (val >>> 0).toString(2).padStart(bits, '0').slice(-bits)
}

function u16(b: Uint8Array, off: number): number {
  return ((b[off] ?? 0) << 8) | (b[off + 1] ?? 0)
}

function u32(b: Uint8Array, off: number): number {
  return (((b[off] ?? 0) << 24) | ((b[off + 1] ?? 0) << 16) | ((b[off + 2] ?? 0) << 8) | (b[off + 3] ?? 0)) >>> 0
}

function ip4Str(b: Uint8Array, off: number): string {
  return `${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}`
}

function macStr(b: Uint8Array, off: number): string {
  return Array.from(b.slice(off, off + 6))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join(':')
}

export function extractHeaderDiagrams(detail: PacketDetail): HeaderDiagramSpec[] {
  const bytes = hexToBytes(detail.rawHex || '')
  const specs: HeaderDiagramSpec[] = []

  for (const layer of detail.layers) {
    const p = layer.protocol.toUpperCase()
    const off = layer.offset

    if (p === 'ETH' && off + 14 <= bytes.length) {
      const et = u16(bytes, off + 12)
      const etMap: Record<number, string> = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: 'VLAN' }
      specs.push({
        protocol: 'Ethernet II',
        titleZh: 'L2 以太网 II 帧首部（14 字节）',
        subtitle: '局域网数据链路层封装：依靠 48 位 MAC 地址在同网段设备/网关间转发',
        osiLayer: 2,
        totalBytes: 14,
        rows: [
          [
            {
              id: 'eth-dst',
              fieldKey: 'eth.dst',
              zhName: '目的 MAC 地址 (48位 / 6B)',
              enShort: 'Destination MAC',
              bitSpan: 32,
              valueText: macStr(bytes, off),
              rawHex: sliceHex(bytes, off, 6),
              rawBin: `${toBin(bytes[off], 8)} ${toBin(bytes[off + 1], 8)} ...`,
              byteOffset: off,
              byteLength: 6,
              highlightTone: 'amber',
            },
          ],
          [
            {
              id: 'eth-src',
              fieldKey: 'eth.src',
              zhName: '源 MAC 地址 (48位 / 6B)',
              enShort: 'Source MAC',
              bitSpan: 22,
              valueText: macStr(bytes, off + 6),
              rawHex: sliceHex(bytes, off + 6, 6),
              rawBin: `${toBin(bytes[off + 6], 8)} ${toBin(bytes[off + 7], 8)} ...`,
              byteOffset: off + 6,
              byteLength: 6,
              highlightTone: 'cyan',
            },
            {
              id: 'eth-type',
              fieldKey: 'eth.type',
              zhName: '类型 (16位)',
              enShort: 'EtherType',
              bitSpan: 10,
              valueText: `0x${et.toString(16).padStart(4, '0')} (${etMap[et] || 'Other'})`,
              rawHex: sliceHex(bytes, off + 12, 2),
              rawBin: toBin(et, 16),
              byteOffset: off + 12,
              byteLength: 2,
              highlightTone: 'violet',
            },
          ],
        ],
      })
    }

    if (p === 'ARP' && off + 28 <= bytes.length) {
      const htype = u16(bytes, off)
      const ptype = u16(bytes, off + 2)
      const hlen = bytes[off + 4]
      const plen = bytes[off + 5]
      const op = u16(bytes, off + 6)
      specs.push({
        protocol: 'ARP',
        titleZh: 'L2/L3 ARP 地址解析报文（28 字节）',
        subtitle: '将 32 位 IPv4 地址解析为 48 位以太网 MAC 地址',
        osiLayer: 2,
        totalBytes: 28,
        rows: [
          [
            {
              id: 'arp-htype',
              fieldKey: 'arp.opcode',
              zhName: '硬件类型 (16位)',
              enShort: 'Hardware Type',
              bitSpan: 16,
              valueText: `${htype} (Ethernet)`,
              rawHex: sliceHex(bytes, off, 2),
              rawBin: toBin(htype, 16),
              byteOffset: off,
              byteLength: 2,
              highlightTone: 'slate',
            },
            {
              id: 'arp-ptype',
              fieldKey: 'eth.type',
              zhName: '协议类型 (16位)',
              enShort: 'Protocol Type',
              bitSpan: 16,
              valueText: `0x${ptype.toString(16).padStart(4, '0')} (IPv4)`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(ptype, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'slate',
            },
          ],
          [
            {
              id: 'arp-hlen',
              fieldKey: 'arp.opcode',
              zhName: '硬件长 (8位)',
              enShort: 'HLEN',
              bitSpan: 8,
              valueText: `${hlen}B`,
              rawHex: sliceHex(bytes, off + 4, 1),
              rawBin: toBin(hlen, 8),
              byteOffset: off + 4,
              byteLength: 1,
              highlightTone: 'slate',
            },
            {
              id: 'arp-plen',
              fieldKey: 'arp.opcode',
              zhName: '协议长 (8位)',
              enShort: 'PLEN',
              bitSpan: 8,
              valueText: `${plen}B`,
              rawHex: sliceHex(bytes, off + 5, 1),
              rawBin: toBin(plen, 8),
              byteOffset: off + 5,
              byteLength: 1,
              highlightTone: 'slate',
            },
            {
              id: 'arp-op',
              fieldKey: 'arp.opcode',
              zhName: '操作码 Opcode (16位)',
              enShort: 'Operation',
              bitSpan: 16,
              valueText: op === 1 ? '1 (ARP 请求 Request)' : op === 2 ? '2 (ARP 响应 Reply)' : String(op),
              rawHex: sliceHex(bytes, off + 6, 2),
              rawBin: toBin(op, 16),
              byteOffset: off + 6,
              byteLength: 2,
              highlightTone: 'amber',
            },
          ],
          [
            {
              id: 'arp-sha',
              fieldKey: 'arp.src.hw_mac',
              zhName: '发送方 MAC (48位)',
              enShort: 'Sender MAC',
              bitSpan: 18,
              valueText: macStr(bytes, off + 8),
              rawHex: sliceHex(bytes, off + 8, 6),
              rawBin: `${toBin(bytes[off + 8], 8)} ...`,
              byteOffset: off + 8,
              byteLength: 6,
              highlightTone: 'cyan',
            },
            {
              id: 'arp-spa',
              fieldKey: 'arp.src.proto_ipv4',
              zhName: '发送方 IP (32位)',
              enShort: 'Sender IP',
              bitSpan: 14,
              valueText: ip4Str(bytes, off + 14),
              rawHex: sliceHex(bytes, off + 14, 4),
              rawBin: toBin(u32(bytes, off + 14), 32),
              byteOffset: off + 14,
              byteLength: 4,
              highlightTone: 'emerald',
            },
          ],
          [
            {
              id: 'arp-tha',
              fieldKey: 'arp.src.hw_mac',
              zhName: '目标 MAC (48位)',
              enShort: 'Target MAC',
              bitSpan: 18,
              valueText: macStr(bytes, off + 18),
              rawHex: sliceHex(bytes, off + 18, 6),
              rawBin: `${toBin(bytes[off + 18], 8)} ...`,
              byteOffset: off + 18,
              byteLength: 6,
              highlightTone: 'slate',
            },
            {
              id: 'arp-tpa',
              fieldKey: 'arp.dst.proto_ipv4',
              zhName: '目标 IP (32位)',
              enShort: 'Target IP',
              bitSpan: 14,
              valueText: ip4Str(bytes, off + 24),
              rawHex: sliceHex(bytes, off + 24, 4),
              rawBin: toBin(u32(bytes, off + 24), 32),
              byteOffset: off + 24,
              byteLength: 4,
              highlightTone: 'violet',
            },
          ],
        ],
      })
    }

    if (p === 'IPV4' && off + 20 <= bytes.length) {
      const ver = bytes[off] >> 4
      const ihl = bytes[off] & 0x0f
      const tos = bytes[off + 1]
      const totLen = u16(bytes, off + 2)
      const ident = u16(bytes, off + 4)
      const flFrag = u16(bytes, off + 6)
      const flags3 = flFrag >> 13
      const fragOff = (flFrag & 0x1fff) * 8
      const ttl = bytes[off + 8]
      const proto = bytes[off + 9]
      const chk = u16(bytes, off + 10)
      const protoMap: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' }

      specs.push({
        protocol: 'IPv4',
        titleZh: `L3 IPv4 经典 32 位首部（${ihl * 4} 字节，5 行 × 32 位）`,
        subtitle: 'RFC 791 网络层核心首部：负责全网路由寻址、防环路（TTL）、分片重组与上层协议分发',
        osiLayer: 3,
        totalBytes: ihl * 4,
        rows: [
          [
            {
              id: 'ip-ver',
              fieldKey: 'ip.version',
              zhName: '版本',
              enShort: 'Ver (4b)',
              bitSpan: 4,
              valueText: `${ver}`,
              rawHex: `0x${ver.toString(16)}`,
              rawBin: toBin(ver, 4),
              byteOffset: off,
              byteLength: 1,
              highlightTone: 'cyan',
            },
            {
              id: 'ip-ihl',
              fieldKey: 'ip.hdr_len',
              zhName: '首部长度',
              enShort: 'IHL (4b)',
              bitSpan: 4,
              valueText: `${ihl} (${ihl * 4}B)`,
              rawHex: `0x${ihl.toString(16)}`,
              rawBin: toBin(ihl, 4),
              byteOffset: off,
              byteLength: 1,
              highlightTone: 'cyan',
            },
            {
              id: 'ip-tos',
              fieldKey: 'ip.dsfield',
              zhName: '区分服务 DSCP/ECN',
              enShort: 'TOS (8b)',
              bitSpan: 8,
              valueText: `0x${tos.toString(16).padStart(2, '0')}`,
              rawHex: sliceHex(bytes, off + 1, 1),
              rawBin: toBin(tos, 8),
              byteOffset: off + 1,
              byteLength: 1,
              highlightTone: 'slate',
            },
            {
              id: 'ip-len',
              fieldKey: 'ip.len',
              zhName: '总长度 Total Length (16位)',
              enShort: 'Total Len',
              bitSpan: 16,
              valueText: `${totLen} 字节`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(totLen, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'emerald',
            },
          ],
          [
            {
              id: 'ip-id',
              fieldKey: 'ip.id',
              zhName: '标识 Identification (16位)',
              enShort: 'ID',
              bitSpan: 16,
              valueText: `0x${ident.toString(16).padStart(4, '0')} (${ident})`,
              rawHex: sliceHex(bytes, off + 4, 2),
              rawBin: toBin(ident, 16),
              byteOffset: off + 4,
              byteLength: 2,
              highlightTone: 'slate',
            },
            {
              id: 'ip-flags',
              fieldKey: 'ip.flags',
              zhName: '标志 (3位)',
              enShort: 'DF/MF',
              bitSpan: 5,
              valueText: `DF=${(flags3 >> 1) & 1} MF=${flags3 & 1}`,
              rawHex: `0x${flags3.toString(16)}`,
              rawBin: toBin(flags3, 3),
              byteOffset: off + 6,
              byteLength: 1,
              highlightTone: 'amber',
            },
            {
              id: 'ip-frag',
              fieldKey: 'ip.flags',
              zhName: '片偏移 Fragment Offset (13位)',
              enShort: 'Frag Offset',
              bitSpan: 11,
              valueText: `${fragOff} 字节`,
              rawHex: sliceHex(bytes, off + 6, 2),
              rawBin: toBin(flFrag & 0x1fff, 13),
              byteOffset: off + 6,
              byteLength: 2,
              highlightTone: 'slate',
            },
          ],
          [
            {
              id: 'ip-ttl',
              fieldKey: 'ip.ttl',
              zhName: '生存时间 TTL (8位)',
              enShort: 'TTL',
              bitSpan: 8,
              valueText: `${ttl} 跳`,
              rawHex: sliceHex(bytes, off + 8, 1),
              rawBin: toBin(ttl, 8),
              byteOffset: off + 8,
              byteLength: 1,
              highlightTone: 'amber',
            },
            {
              id: 'ip-proto',
              fieldKey: 'ip.proto',
              zhName: '协议 (8位)',
              enShort: 'Proto',
              bitSpan: 8,
              valueText: `${proto} (${protoMap[proto] || 'Other'})`,
              rawHex: sliceHex(bytes, off + 9, 1),
              rawBin: toBin(proto, 8),
              byteOffset: off + 9,
              byteLength: 1,
              highlightTone: 'violet',
            },
            {
              id: 'ip-chk',
              fieldKey: 'ip.checksum',
              zhName: '首部校验和 Header Checksum (16位)',
              enShort: 'Checksum',
              bitSpan: 16,
              valueText: `0x${chk.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off + 10, 2),
              rawBin: toBin(chk, 16),
              byteOffset: off + 10,
              byteLength: 2,
              highlightTone: 'emerald',
            },
          ],
          [
            {
              id: 'ip-src',
              fieldKey: 'ip.src',
              zhName: '源 IP 地址 Source Address (32位)',
              enShort: 'Source IP',
              bitSpan: 32,
              valueText: ip4Str(bytes, off + 12),
              rawHex: sliceHex(bytes, off + 12, 4),
              rawBin: `${toBin(bytes[off + 12], 8)}.${toBin(bytes[off + 13], 8)}.${toBin(bytes[off + 14], 8)}.${toBin(bytes[off + 15], 8)}`,
              byteOffset: off + 12,
              byteLength: 4,
              highlightTone: 'cyan',
            },
          ],
          [
            {
              id: 'ip-dst',
              fieldKey: 'ip.dst',
              zhName: '目的 IP 地址 Destination Address (32位)',
              enShort: 'Destination IP',
              bitSpan: 32,
              valueText: ip4Str(bytes, off + 16),
              rawHex: sliceHex(bytes, off + 16, 4),
              rawBin: `${toBin(bytes[off + 16], 8)}.${toBin(bytes[off + 17], 8)}.${toBin(bytes[off + 18], 8)}.${toBin(bytes[off + 19], 8)}`,
              byteOffset: off + 16,
              byteLength: 4,
              highlightTone: 'violet',
            },
          ],
        ],
      })
    }

    if (p === 'TCP' && off + 20 <= bytes.length) {
      const sp = u16(bytes, off)
      const dp = u16(bytes, off + 2)
      const seq = u32(bytes, off + 4)
      const ack = u32(bytes, off + 8)
      const offFlags = u16(bytes, off + 12)
      const doff = (offFlags >> 12) & 0xf
      const flags6 = offFlags & 0x3f
      const win = u16(bytes, off + 14)
      const chk = u16(bytes, off + 16)
      const urg = u16(bytes, off + 18)
      const flagNames = ['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'].filter((_, i) => (flags6 >> (5 - i)) & 1)

      specs.push({
        protocol: 'TCP',
        titleZh: `L4 TCP 经典 32 位首部（${doff * 4} 字节，对应教材图 12-3）`,
        subtitle: 'RFC 9293 可靠字节流传输首部：序号/确认号保障不丢不乱，标志位控握手，窗口控流量',
        osiLayer: 4,
        totalBytes: doff * 4,
        rows: [
          [
            {
              id: 'tcp-sp',
              fieldKey: 'tcp.srcport',
              zhName: '源端口 Source Port (16位)',
              enShort: 'Src Port',
              bitSpan: 16,
              valueText: `${sp}`,
              rawHex: sliceHex(bytes, off, 2),
              rawBin: toBin(sp, 16),
              byteOffset: off,
              byteLength: 2,
              highlightTone: 'cyan',
            },
            {
              id: 'tcp-dp',
              fieldKey: 'tcp.dstport',
              zhName: '目的端口 Dest Port (16位)',
              enShort: 'Dst Port',
              bitSpan: 16,
              valueText: `${dp}`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(dp, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'violet',
            },
          ],
          [
            {
              id: 'tcp-seq',
              fieldKey: 'tcp.seq',
              zhName: '序列号 Sequence Number (32位)',
              enShort: 'Seq',
              bitSpan: 32,
              valueText: `原始 ${seq} (相对 Seq=${detail.layers.find((l) => l.protocol === 'TCP')?.fields.find((f) => f.key === 'tcp.seq')?.value ?? seq})`,
              rawHex: sliceHex(bytes, off + 4, 4),
              rawBin: toBin(seq, 32),
              byteOffset: off + 4,
              byteLength: 4,
              highlightTone: 'emerald',
            },
          ],
          [
            {
              id: 'tcp-ack',
              fieldKey: 'tcp.ack',
              zhName: '确认号 Acknowledgment Number (32位)',
              enShort: 'Ack',
              bitSpan: 32,
              valueText: `原始 ${ack} (相对 Ack=${detail.layers.find((l) => l.protocol === 'TCP')?.fields.find((f) => f.key === 'tcp.ack')?.value ?? ack})`,
              rawHex: sliceHex(bytes, off + 8, 4),
              rawBin: toBin(ack, 32),
              byteOffset: off + 8,
              byteLength: 4,
              highlightTone: 'cyan',
            },
          ],
          [
            {
              id: 'tcp-doff',
              fieldKey: 'tcp.hdr_len',
              zhName: '首部长度',
              enShort: 'Off(4b)',
              bitSpan: 5,
              valueText: `${doff} (${doff * 4}B)`,
              rawHex: `0x${doff.toString(16)}`,
              rawBin: toBin(doff, 4),
              byteOffset: off + 12,
              byteLength: 1,
              highlightTone: 'slate',
            },
            {
              id: 'tcp-flags',
              fieldKey: 'tcp.flags',
              zhName: '控制标志位 (URG/ACK/PSH/RST/SYN/FIN)',
              enShort: 'Flags',
              bitSpan: 11,
              valueText: flagNames.length ? flagNames.join(' · ') : 'NONE (0x00)',
              rawHex: sliceHex(bytes, off + 12, 2),
              rawBin: toBin(flags6, 6),
              byteOffset: off + 12,
              byteLength: 2,
              highlightTone: flagNames.includes('RST') ? 'rose' : flagNames.includes('SYN') ? 'amber' : 'violet',
            },
            {
              id: 'tcp-win',
              fieldKey: 'tcp.window_size',
              zhName: '滑动窗口大小 Window (16位)',
              enShort: 'Window',
              bitSpan: 16,
              valueText: `${win} 字节`,
              rawHex: sliceHex(bytes, off + 14, 2),
              rawBin: toBin(win, 16),
              byteOffset: off + 14,
              byteLength: 2,
              highlightTone: win === 0 ? 'rose' : 'emerald',
            },
          ],
          [
            {
              id: 'tcp-chk',
              fieldKey: 'tcp.checksum',
              zhName: 'TCP 校验和 (16位)',
              enShort: 'Checksum',
              bitSpan: 16,
              valueText: `0x${chk.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off + 16, 2),
              rawBin: toBin(chk, 16),
              byteOffset: off + 16,
              byteLength: 2,
              highlightTone: 'slate',
            },
            {
              id: 'tcp-urg',
              fieldKey: 'tcp.flags',
              zhName: '紧急指针 Urgent Pointer (16位)',
              enShort: 'Urgent',
              bitSpan: 16,
              valueText: `${urg}`,
              rawHex: sliceHex(bytes, off + 18, 2),
              rawBin: toBin(urg, 16),
              byteOffset: off + 18,
              byteLength: 2,
              highlightTone: 'slate',
            },
          ],
        ],
      })
    }

    if (p === 'UDP' && off + 8 <= bytes.length) {
      const sp = u16(bytes, off)
      const dp = u16(bytes, off + 2)
      const ulen = u16(bytes, off + 4)
      const chk = u16(bytes, off + 6)
      specs.push({
        protocol: 'UDP',
        titleZh: 'L4 UDP 极简 32 位首部（仅 8 字节！）',
        subtitle: 'RFC 768 无连接传输：没有握手、没有序号、没有重传，极致低延迟（对比 TCP 的 20 字节首部）',
        osiLayer: 4,
        totalBytes: 8,
        rows: [
          [
            {
              id: 'udp-sp',
              fieldKey: 'udp.srcport',
              zhName: '源端口 Source Port (16位)',
              enShort: 'Src Port',
              bitSpan: 16,
              valueText: `${sp}`,
              rawHex: sliceHex(bytes, off, 2),
              rawBin: toBin(sp, 16),
              byteOffset: off,
              byteLength: 2,
              highlightTone: 'cyan',
            },
            {
              id: 'udp-dp',
              fieldKey: 'udp.dstport',
              zhName: '目的端口 Dest Port (16位)',
              enShort: 'Dst Port',
              bitSpan: 16,
              valueText: `${dp}`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(dp, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'violet',
            },
          ],
          [
            {
              id: 'udp-len',
              fieldKey: 'udp.length',
              zhName: 'UDP 总长度 (16位)',
              enShort: 'Length',
              bitSpan: 16,
              valueText: `${ulen} 字节 (首部8 + 载荷${Math.max(0, ulen - 8)})`,
              rawHex: sliceHex(bytes, off + 4, 2),
              rawBin: toBin(ulen, 16),
              byteOffset: off + 4,
              byteLength: 2,
              highlightTone: 'emerald',
            },
            {
              id: 'udp-chk',
              fieldKey: 'tcp.checksum',
              zhName: '校验和 Checksum (16位)',
              enShort: 'Checksum',
              bitSpan: 16,
              valueText: `0x${chk.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off + 6, 2),
              rawBin: toBin(chk, 16),
              byteOffset: off + 6,
              byteLength: 2,
              highlightTone: 'slate',
            },
          ],
        ],
      })
    }

    if (p === 'DNS' && off + 12 <= bytes.length) {
      const txid = u16(bytes, off)
      const fl = u16(bytes, off + 2)
      const qd = u16(bytes, off + 4)
      const an = u16(bytes, off + 6)
      const ns = u16(bytes, off + 8)
      const ar = u16(bytes, off + 10)
      const isResp = (fl >> 15) & 1
      specs.push({
        protocol: 'DNS',
        titleZh: 'L7 DNS 报文固定首部（12 字节）',
        subtitle: 'RFC 1035：包含 16 位事务 ID、查询/响应标志与四类资源记录计数',
        osiLayer: 7,
        totalBytes: 12,
        rows: [
          [
            {
              id: 'dns-id',
              fieldKey: 'dns.id',
              zhName: '事务 ID (16位)',
              enShort: 'Transaction ID',
              bitSpan: 16,
              valueText: `0x${txid.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off, 2),
              rawBin: toBin(txid, 16),
              byteOffset: off,
              byteLength: 2,
              highlightTone: 'cyan',
            },
            {
              id: 'dns-fl',
              fieldKey: 'dns.qry.name',
              zhName: '标志 Flags (16位)',
              enShort: 'QR/Opcode/RCODE',
              bitSpan: 16,
              valueText: `0x${fl.toString(16).padStart(4, '0')} (${isResp ? '响应 Response' : '查询 Query'})`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(fl, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'violet',
            },
          ],
          [
            {
              id: 'dns-qd',
              fieldKey: 'dns.qry.name',
              zhName: '问题数 QDCOUNT',
              enShort: 'Questions',
              bitSpan: 16,
              valueText: `${qd} 条查询`,
              rawHex: sliceHex(bytes, off + 4, 2),
              rawBin: toBin(qd, 16),
              byteOffset: off + 4,
              byteLength: 2,
              highlightTone: 'emerald',
            },
            {
              id: 'dns-an',
              fieldKey: 'dns.a',
              zhName: '回答数 ANCOUNT',
              enShort: 'Answers',
              bitSpan: 16,
              valueText: `${an} 条回答`,
              rawHex: sliceHex(bytes, off + 6, 2),
              rawBin: toBin(an, 16),
              byteOffset: off + 6,
              byteLength: 2,
              highlightTone: 'amber',
            },
          ],
          [
            {
              id: 'dns-ns',
              fieldKey: 'dns.qry.name',
              zhName: '权威记录数 NSCOUNT',
              enShort: 'Authority',
              bitSpan: 16,
              valueText: `${ns}`,
              rawHex: sliceHex(bytes, off + 8, 2),
              rawBin: toBin(ns, 16),
              byteOffset: off + 8,
              byteLength: 2,
              highlightTone: 'slate',
            },
            {
              id: 'dns-ar',
              fieldKey: 'dns.qry.name',
              zhName: '附加记录数 ARCOUNT',
              enShort: 'Additional',
              bitSpan: 16,
              valueText: `${ar}`,
              rawHex: sliceHex(bytes, off + 10, 2),
              rawBin: toBin(ar, 16),
              byteOffset: off + 10,
              byteLength: 2,
              highlightTone: 'slate',
            },
          ],
        ],
      })
    }

    if (p === 'ICMP' && off + 8 <= bytes.length) {
      const itype = bytes[off]
      const icode = bytes[off + 1]
      const chk = u16(bytes, off + 2)
      const id = u16(bytes, off + 4)
      const seq = u16(bytes, off + 6)
      specs.push({
        protocol: 'ICMP',
        titleZh: 'L3 ICMP 控制报文首部（8 字节）',
        subtitle: 'Ping / Traceroute 核心协议：直接嵌套在 IPv4 载荷中',
        osiLayer: 3,
        totalBytes: 8,
        rows: [
          [
            {
              id: 'icmp-type',
              fieldKey: 'icmp.type',
              zhName: '类型 Type (8位)',
              enShort: 'Type',
              bitSpan: 8,
              valueText: `${itype} (${itype === 8 ? 'Ping请求' : itype === 0 ? 'Ping应答' : '控制消息'})`,
              rawHex: sliceHex(bytes, off, 1),
              rawBin: toBin(itype, 8),
              byteOffset: off,
              byteLength: 1,
              highlightTone: 'violet',
            },
            {
              id: 'icmp-code',
              fieldKey: 'icmp.type',
              zhName: '代码 Code (8位)',
              enShort: 'Code',
              bitSpan: 8,
              valueText: `${icode}`,
              rawHex: sliceHex(bytes, off + 1, 1),
              rawBin: toBin(icode, 8),
              byteOffset: off + 1,
              byteLength: 1,
              highlightTone: 'slate',
            },
            {
              id: 'icmp-chk',
              fieldKey: 'ip.checksum',
              zhName: '校验和 Checksum (16位)',
              enShort: 'Checksum',
              bitSpan: 16,
              valueText: `0x${chk.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off + 2, 2),
              rawBin: toBin(chk, 16),
              byteOffset: off + 2,
              byteLength: 2,
              highlightTone: 'emerald',
            },
          ],
          [
            {
              id: 'icmp-id',
              fieldKey: 'icmp.type',
              zhName: '标识符 Identifier (16位)',
              enShort: 'ID',
              bitSpan: 16,
              valueText: `0x${id.toString(16).padStart(4, '0')}`,
              rawHex: sliceHex(bytes, off + 4, 2),
              rawBin: toBin(id, 16),
              byteOffset: off + 4,
              byteLength: 2,
              highlightTone: 'cyan',
            },
            {
              id: 'icmp-seq',
              fieldKey: 'icmp.type',
              zhName: '序号 Sequence (16位)',
              enShort: 'Seq',
              bitSpan: 16,
              valueText: `${seq}`,
              rawHex: sliceHex(bytes, off + 6, 2),
              rawBin: toBin(seq, 16),
              byteOffset: off + 6,
              byteLength: 2,
              highlightTone: 'amber',
            },
          ],
        ],
      })
    }
  }

  return specs
}

/**
 * 自动从当前用户抓包中挖掘出的「计网互动实战课程」
 */
export interface DiscoveredLesson {
  id: string
  badge: string
  title: string
  subtitle: string
  color: 'cyan' | 'emerald' | 'violet' | 'amber' | 'rose'
  packetNos: number[]
  streamRef?: { proto: 'tcp' | 'udp'; streamId: number }
  steps: { packetNo: number; label: string; explain: string }[]
}

export function discoverLearningLessons(
  packets: PacketSummary[],
  streams: StreamSummary[],
): DiscoveredLesson[] {
  const lessons: DiscoveredLesson[] = []

  // 1. TCP Complete Lifecycle (Handshake + Data/Retransmission + FIN)
  const bestTcp =
    streams.find((s) => s.proto === 'tcp' && s.retransmissions > 0) ||
    streams.find((s) => s.proto === 'tcp' && s.packets >= 4 && s.totalBytes > 0) ||
    streams.find((s) => s.proto === 'tcp' && s.packets >= 3)

  if (bestTcp) {
    const spkts = packets.filter((p) => p.streamProto === 'tcp' && p.streamId === bestTcp.streamId)
    lessons.push({
      id: 'tcp-lifecycle',
      badge: 'L4 传输层核心',
      title: `TCP 完整生命周期实景剖析（流 #${bestTcp.streamId} · ${bestTcp.appProtocol}）`,
      subtitle: `${bestTcp.client} ↔ ${bestTcp.server} · 共 ${spkts.length} 帧${bestTcp.rttMs !== null ? ` · 握手 RTT ${bestTcp.rttMs}ms` : ''}${bestTcp.retransmissions > 0 ? ` · 含 ${bestTcp.retransmissions} 次重传` : ''}`,
      color: 'cyan',
      packetNos: spkts.map((p) => p.no),
      streamRef: { proto: 'tcp', streamId: bestTcp.streamId },
      steps: spkts.slice(0, 10).map((p) => {
        let explain = p.info
        if (p.tcpFlags.includes('SYN') && !p.tcpFlags.includes('ACK')) {
          explain = '① 三次握手第 1 步（SYN）：客户端进入 SYN_SENT 状态，发送初始序号。'
        } else if (p.tcpFlags.includes('SYN') && p.tcpFlags.includes('ACK')) {
          explain = '② 三次握手第 2 步（SYN+ACK）：服务端同意建连并回复自己的初始序号，客户端据此测出 RTT。'
        } else if (p.tcpExpert.some((e) => e.includes('Retrans'))) {
          explain = '⚠️ 可靠传输触发重传：发送方重发已发送过的序号区间，WirePulse 重组流时会自动去重！'
        } else if (p.tcpFlags.includes('FIN')) {
          explain = '👋 四次挥手（FIN）：单向关闭数据通道，FIN 标志消耗 1 个序列号。'
        } else if (p.protocol === 'HTTP') {
          explain = `📨 承载应用层明文数据：${p.info.slice(0, 72)}`
        } else if (p.protocol.startsWith('TLS')) {
          explain = `🔐 承载 TLS 安全握手/加密数据：${p.info.slice(0, 72)}`
        }
        return { packetNo: p.no, label: `帧 #${p.no} [${p.protocol} ${p.tcpFlags}]`, explain }
      }),
    })
  }

  // 2. HTTP 明文 vs HTTPS/TLS 加密对照实验
  const httpPkt = packets.find((p) => p.protocol === 'HTTP')
  const tlsCh = packets.find((p) => p.protocol.startsWith('TLS') && p.info.includes('Client Hello'))
  const tlsApp = packets.find((p) => p.protocol.startsWith('TLS') && p.info.includes('Application Data'))
  if (httpPkt && (tlsCh || tlsApp)) {
    const steps: { packetNo: number; label: string; explain: string }[] = [
      {
        packetNo: httpPkt.no,
        label: `明文对照：帧 #${httpPkt.no} (HTTP)`,
        explain: `未加密 HTTP 流量：右侧 ASCII 可直接读出请求方法、路径与头部（${httpPkt.info.slice(0, 60)}），存在窃听风险。`,
      },
    ]
    if (tlsCh) {
      steps.push({
        packetNo: tlsCh.no,
        label: `加密握手：帧 #${tlsCh.no} (${tlsCh.protocol})`,
        explain: `TLS Client Hello 阶段：明文协商密码套件与 SNI 域名（${tlsCh.info}），尚未加密业务正文。`,
      })
    }
    if (tlsApp) {
      steps.push({
        packetNo: tlsApp.no,
        label: `密文传输：帧 #${tlsApp.no} (${tlsApp.protocol})`,
        explain: `握手完成后 Application Data 全部变为高熵密文，中间人即使截获也无法直接还原明文！`,
      })
    }
    lessons.push({
      id: 'http-vs-tls',
      badge: 'L6/L7 安全对照',
      title: '明文 HTTP vs 加密 HTTPS/TLS 抓包直观对比',
      subtitle: '同一份抓包中亲眼见证「为何必须使用 HTTPS」与「TLS 握手暴露了哪些元数据」',
      color: 'violet',
      packetNos: steps.map((s) => s.packetNo),
      steps,
    })
  }

  // 3. DNS 域名解析之旅
  const dnsPkts = packets.filter((p) => p.protocol === 'DNS' || p.protocol === 'mDNS').slice(0, 6)
  if (dnsPkts.length > 0) {
    lessons.push({
      id: 'dns-journey',
      badge: 'L7 互联网电话簿',
      title: `DNS 域名解析实录（发现 ${dnsPkts.length} 帧）`,
      subtitle: '观察 UDP 53 端口上「域名 → IP 地址」的一问一答过程与事务 ID 匹配',
      color: 'emerald',
      packetNos: dnsPkts.map((p) => p.no),
      steps: dnsPkts.map((p) => ({
        packetNo: p.no,
        label: `帧 #${p.no} (${p.info.includes('response') ? '响应' : '查询'})`,
        explain: `${p.src} → ${p.dst}：${p.info}`,
      })),
    })
  }

  // 4. ARP 局域网寻址与欺骗原理
  const arpPkts = packets.filter((p) => p.protocol === 'ARP').slice(0, 5)
  if (arpPkts.length > 0) {
    lessons.push({
      id: 'arp-lan',
      badge: 'L2 数据链路层',
      title: `ARP 局域网寻址实录（发现 ${arpPkts.length} 帧）`,
      subtitle: '理解局域网通信为何同时需要 IP 与 MAC，以及 ARP 欺骗如何劫持流量',
      color: 'amber',
      packetNos: arpPkts.map((p) => p.no),
      steps: arpPkts.map((p) => ({
        packetNo: p.no,
        label: `帧 #${p.no}${p.alertSeverity ? ' ⚠️ 告警' : ''}`,
        explain: p.alertSeverity
          ? `⚠️ 检测到 ARP 欺骗：${p.info}（同一网关 IP 出现异常 MAC 变更！）`
          : `${p.src} → ${p.dst}：${p.info}`,
      })),
    })
  }

  // 5. 网络攻击真实报文解剖
  const alertPkts = packets.filter((p) => p.alertSeverity === 'CRITICAL' || p.alertSeverity === 'HIGH').slice(0, 6)
  if (alertPkts.length > 0) {
    lessons.push({
      id: 'security-lab',
      badge: '安全实战课堂',
      title: `从真实报文中识破网络攻击（${alertPkts.length} 个典型案例）`,
      subtitle: '点击逐条解剖 SQL 注入、明文凭证泄露、端口扫描与 DNS 隧道的底层报文特征',
      color: 'rose',
      packetNos: alertPkts.map((p) => p.no),
      steps: alertPkts.map((p) => ({
        packetNo: p.no,
        label: `帧 #${p.no} [${p.alertSeverity}] ${p.alertRules[0] || ''}`,
        explain: `${p.src} → ${p.dst} (${p.protocol})：${p.info.slice(0, 88)}`,
      })),
    })
  }

  return lessons
}

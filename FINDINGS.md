# OmniSight 分析发现 — 三角洲行动 (Delta Force)

> 基于静态分析 (`omnisight-disasm`) 结果整理
> 更新时间: 2026-07-03

---

## 基础信息

| 项目 | 值 |
|---|---|
| 游戏名称 | 三角洲行动 (Delta Force: Hawk Ops) |
| 开发商 | 腾讯天美工作室群 (TiMi Studio Group) |
| 包名 | `com.tencent.tmgp.dfm` |
| 版本 | `1.201.37114.81` |
| APK 大小 | 1,493,989,392 bytes (~1.4 GB) |
| 目标架构 | arm64-v8a |
| 引擎 | **Unreal Engine 5** (导出为 `libUE4.so`) |

---

## 引擎检测

`libUE4.so` 被标记为 UE5 的依据：
- 二进制字符串中存在 UE5 版本标识
- `libPxExtJava.so` 中 JNI 载入 `com/epicgames/ue4/GameActivity`
- UE5 移动端仍以 `libUE4.so` 命名向前兼容

**UE5 模块统计 (libUE4.so):**
- 导出符号: 91 个
- 导入符号: 834 个
- 提取字符串: 2,258 条
- Sections: 23 个

**关键依赖库 (85 个 ELF 模块):**

| 库 | 用途 |
|---|---|
| `libUE4.so` | Unreal Engine (UE5) 核心 |
| `libtersafe.so` | ACE 反作弊核心 |
| `libtprt.so` | ACE 运行时 |
| `libCrashSight.so` | 崩溃上报 |
| `libGCloudVoice.so` | 腾讯云语音 |
| `libgcloud.so` / `libgcloudcore.so` | 腾讯云 SDK |
| `libMSDKPIXCore.so` | 腾讯 MSDK 多平台 SDK 核心 |
| `libMSDKPIXWechat.so` | 微信 SDK |
| `libMSDKPIXQQ.so` | QQ SDK |
| `libgamemaster.so` | 腾讯 GameMaster 性能优化 |
| `libtgpa.so` | 腾讯 GPA 性能监测 |
| `libPcdnTegTransSdk.so` | P2P CDN 资源加速 |
| `libPixFFmpeg.so` / `libPixVideo.so` | 视频播放 (FFmpeg) |
| `libAk*.so` (25 个) | Wwise 音频中间件 |
| `libRoosterNN.so` | 神经网络推理 |
| `libsnapdragon_services_*.so` | 高通骁龙优化 |

---

## AndroidManifest

- **Main Activity**: `com.epicgames.ue4.SplashActivity`
- **权限**: 37 个（INTERNET、WRITE_EXTERNAL_STORAGE、RECORD_AUDIO 等）
- **服务**: 18 个（推送、支付、下载等）
- **接收器**: 10 个（推送、闹钟等）

---

## ACE 反作弊 (Anti-Cheat Expert)

确认使用腾讯 ACE 反作弊，证据：

| 证据 | 来源 |
|---|---|
| 包名 `com.ace.gamesafe4` | `libtersafe.so` 字符串 |
| ACE 构建路径 | `libtersafe.so` 中 `.../mvm/source/VM/Memory/BopMemoryOperation.cpp` |
| `debugger` / `ptrace` 检测 | `libtersafe.so` 字符串 |
| 数据文件 `a64.datPK` / `a64.sigPK` | `libtprt.so` 引用 |
| `libtersafe.so` 引用 | `libtprt.so` 中 `libtersafe.so` 字符串 |

ACE 相关库:

| 库 | 字符串数 | 说明 |
|---|---|---|
| `libtersafe.so` | 3,869 | ACE 主引擎（含 JPEG 库混淆） |
| `libtprt.so` | 304 | ACE 运行时（引用 tersafe + 数据文件） |

详情: `apks/report/ace_analysis.md`

---

## Protobuf 协议分析

**关键发现**: 187 个命名空间、466 个 protobuf 类型引用，**全部为 SDK 协议**。

| 命名空间 | 类型数 | 用途 |
|---|---|---|
| `SightPkg` | 23 | **CrashSight 崩溃上报**（非游戏协议） |
| `GCloud` | 24 | 腾讯云 SDK（登录/内购/社交） |
| `MicroMsg` | 77 | 微信通信协议 |
| `Config` | 33 | 配置协议 |
| `AppSession` | 2 | 会话管理 |
| `GameActivity` | 7 | UE JNI 桥接 |
| `PufferUpdateService` | 10 | P2P 更新 |
| `VersionUpdate` | 18 | 版本更新 |
| `GVoiceWSS` | 3 | 语音 WebSocket |
| `TPUSH` | 6 | 腾讯推送 |

**游戏协议结论**: 三角洲行动的网络协议很可能**不是标准 protobuf**，推测使用:
- 自定义二进制协议（基于 TCP/KCP/WebSocket）
- UE5 `Iris` 复制框架
- 或 protobuf 但类型名被混淆剥离

详情: `apks/proto/SUMMARY.md` 及 `apks/proto/*.proto`

---

## 网络端点

| 类别 | 数量 | 说明 |
|---|---|---|
| URL | 42 | 含游戏相关端点 |
| IP:Port | 10 | 硬编码 IP |
| 域名 | 4,657 | 经过 protobuf 去重 |

**腾讯系域名 (352 个)** 示例:
- `cloud.tgpa.qq.com` — 腾讯 GPA 云端
- `tauth.qq.com` — QQ 登录
- `api.unipay.qq.com` — 腾讯支付
- `analy.qq.com` — 腾讯分析
- `appsupport.qq.com` — 应用支持
- `imgcache.qq.com` — 图片 CDN

**扫描检测到的网络协议**:
- TCP / UDP / WebSocket
- KCP (可靠 UDP)
- QUIC (HTTP/3)
- gRPC (HTTP/2)

详情: `apks/report/network_endpoints.md`

---

## DEX (Java/Kotlin 代码)

| 项目 | 值 |
|---|---|
| DEX 文件数 | 多个 (Split APK) |
| 总类数 | 10,198 |
| 总方法数 | 51,273（含签名） |

类名被 **ProGuard/R8 重度混淆**（`La/b;`、`La0/a;` 等），游戏自身逻辑难以直接追溯。

---

## 后续建议

1. **抓包分析**: 运行游戏 + mitmproxy / PCAP 捕获，确定实际协议格式
2. **DEX 反混淆**: jadx 反编译 DEX，在网络相关类中定位协议处理逻辑
3. **ACE 绕过评估**: 评估 frida / 注入工具在 ACE 防护下的可用性
4. **UE5 内存分析**: 运行时读取 GName / GObjects 获取类型信息

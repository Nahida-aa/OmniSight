# OmniSight 实施计划

## 环境搭建
- [x] 检查 Rust / Bun / adb 环境
- [x] 初始化 Rust 工作区（Cargo workspace）
- [x] 初始化 Bun scripts 包
- [x] 编写 APK 提取脚本（`scripts/pull-apk.ts`）

## Phase 1: 静态分析 (disasm) — 已完成

### APK 基础解析
- [x] APK 解包（zip crate）
- [x] AndroidManifest.xml 二进制 AXML 解析（入口、权限、services、receivers）
- [x] DEX 解析：类列表 + 方法签名 + 字符串常量池（含 class_data_off 跟随）

### ELF 分析
- [x] 枚举所有 .so，识别主引擎（libUE4.so → UE5）
- [x] 符号表提取：导出函数、导入函数、动态符号
- [x] 字符串表提取：rodata / strtab 段可打印字符串
- [ ] 反调试/加固识别（部分实现，ACE 关键词已提取，需系统化）

### 信息提取
- [x] 网络端点扫描：URL、IP、域名
- [x] 加密相关：AES、RSA、密钥关键词
- [x] Protobuf 描述符扫描（源码语法 + 编译后 PascalCase 类型引用）
- [x] 协议关键字：opcode、packet、session、token 等 30+

### UE 引擎专项（三角洲行动 UE5）
- [ ] GName 表偏移扫描
- [ ] GObjects 数组扫描
- [ ] UObject/UFunction 模式识别

### 输出
- [x] JSON 报告生成
- [x] Markdown 可读报告（`scripts/gen_report_md.ts`）

## 对三角洲行动的深入分析

### SightPkg 协议还原
- [x] 提取 466 个 protobuf 类型名，按命名空间分组（`scripts/analyze_proto.ts` → `apks/proto/*.proto`）
- [x] 分类 SDK 协议 vs 游戏协议：187 命名空间全为 SDK 协议，游戏协议非 protobuf
- [ ] 需要抓包或 DEX 反向确定游戏实际协议格式
- [ ] 根据字符串上下文推断字段编号
- [ ] 生成 .proto 文件框架

### 网络端点挖掘
- [x] 从扫描结果筛出真实服务端地址（`scripts/analyze_network.ts` → `apks/report/network_endpoints.md`）
- [ ] 区分腾讯云 / CDN / 游戏服
- [ ] 推测协议类型（TCP/WebSocket/KCP）

### ACE 反作弊对抗
- [x] 系统整理 libtersafe.so 检测点（`scripts/analyze_ace.ts` → `apks/report/ace_analysis.md`）
- [ ] 分类：进程检测 / 内存检测 / 网络检测 / 文件检测（半自动，需人工精筛）
- [ ] 分类：进程检测 / 内存检测 / 网络检测 / 文件检测
- [ ] 整理已知绕过方案

### UE5 引擎偏移
- [x] GName 表特征字符串扫描（`scripts/analyze_ue5.ts` → `apks/report/ue5_analysis.md`）
- [ ] GObjects 数组模式识别
- [ ] UObject / UFunction 虚表定位

## Phase 2: 日志分析 (trace) — 已实现
- [x] logcat 采集器（adb logcat 解析，支持 PID 过滤）
- [x] 关键字匹配（支持加载 report.json + CLI 额外关键字）
- [x] 匹配统计输出 + JSON 报告保存
- [ ] 日志与静态分析结果关联（report.json 模式加载已完成，待实机验证）

## Phase 3: 网络分析 (packet)
- [ ] mitmproxy 环境搭建
- [ ] 测试 WiFi 代理直连（不修改 APK）
- [ ] 如有必要：修改 Network Security Config 重打包
- [ ] 流量录制 + 协议解析框架

## (推迟) Phase 4: 内存分析
- [ ] 根据前面成果评估可行性

## 通用
- [ ] README.md 使用文档
- [x] 分析报告生成脚本（`scripts/gen_report_md.ts`）


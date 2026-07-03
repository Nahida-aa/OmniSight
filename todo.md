# OmniSight 实施计划

## 环境搭建
- [x] 检查 Rust / Bun / adb 环境
- [ ] 初始化 Rust 工作区（Cargo workspace）
- [ ] 初始化 Bun scripts 包
- [ ] 编写 APK 提取脚本

## Phase 1: 静态分析 (disasm) — 无风险
### APK 基础解析
- [ ] APK 解包（zip crate）
- [ ] AndroidManifest.xml 解析（入口、权限、network config）
- [ ] DEX 解析：类列表、方法签名、字符串常量池

### ELF 分析
- [ ] 枚举所有 .so，识别主引擎（libUE4.so / libUnity.so / 自研）
- [ ] 符号表提取：导出函数、导入函数、动态符号
- [ ] 字符串表提取：rodata 段可打印字符串
- [ ] 反调试/加固识别

### 信息提取
- [ ] 网络端点扫描：URL、IP、域名、端口
- [ ] 加密相关：AES S-box、RSA 公钥、自定义常数
- [ ] Protobuf 描述符扫描
- [ ] 协议关键字：opcode、packet、session、token

### UE 引擎专项（如果是 UE）
- [ ] GName 表偏移扫描
- [ ] GObjects 数组扫描
- [ ] UObject/UFunction 模式识别

### 输出
- [ ] JSON 报告生成
- [ ] Markdown 可读报告

## Phase 2: 日志分析 (trace) — 极低风险
- [ ] logcat 收集器（adb logcat 解析）
- [ ] 应用文件日志拉取
- [ ] 关键词匹配 + 异常频率检测
- [ ] 日志与静态分析结果关联

## Phase 3: 网络分析 (packet) — 风险递增
- [ ] mitmproxy 环境搭建
- [ ] 测试 WiFi 代理直连（不修改 APK）
- [ ] 如有必要：修改 Network Security Config 重打包
- [ ] 流量录制 + 协议解析框架

## (推迟) Phase 4: 内存分析
- [ ] 根据前面成果评估可行性

## 通用
- [ ] README.md 使用文档
- [ ] 分析报告模板

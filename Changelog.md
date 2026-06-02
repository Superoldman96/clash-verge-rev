## v2.5.2

### 🐞 修复问题

- macOS 托盘速率可能的样式错误
- 修复订阅 TLS 1.0/1.1 等过旧协议时显示更明确错误原因
- 修复 gzip 压缩订阅响应被当作无效 YAML 导致导入失败的问题
- 修复订阅 URL 使用空密码 Basic Auth 时未发送认证信息的问题
- Linux 托盘可能与其他 tauri 程序托盘冲突导致图标异常

<details>
<summary><strong> ✨ 新增功能 </strong></summary>

- 增加 TrustTunnel, OpenVPN, Tailscale, GostRelay 节点显示支持
- 新增 CVD 订阅设备绑定与加密下发支持，降低订阅链接泄露后的持续滥用风险。了解更多：[CVD 方案介绍](./docs/cvd-protocol-introduction.md)；订阅服务开发者请参考：[服务端集成文档](./docs/cvd-server-integration.md)。

</details>

<details>
<summary><strong> 🚀 优化改进 </strong></summary>

- 关闭 autofill 弹出窗口

</details>

# CVD 服务端集成技术文档（订阅服务对接）

**CVD = Clash Verge Device-binding Protocol** · 协议版本 `X-CVD-Ver: 1`
**适用对象**：订阅服务（**board / 自研面板等）的后端开发者
**目的**：让面板按本文实现「向已注册设备公钥下发 HPKE 加密订阅」的服务端逻辑，与 Clash Verge 客户端互通。
**权威来源**：本文所有协议常量、字节格式、校验规则均与 Clash Verge 客户端当前实现严格一致（`src-tauri/src/cvd/mod.rs`）。如有歧义，以 §14 的互操作测试向量（KAT）为准。

---

## 0. 30 秒速览

1. Clash Verge 客户端会在新建 / 导入订阅、手动更新未注册订阅，以及已注册订阅的后续更新中自动附加 `X-CVD-*` 请求头，携带一个 32 字节 X25519 设备公钥。
2. 面板收到后可以：用该公钥把订阅 YAML 做 **HPKE（RFC 9180）加密**后返回；或返回明文（客户端自动按「不支持 CVD」处理）。
3. 面板按 `(token, 公钥)` 维护「设备槽位」，可设上限；超限返回 `403 device_limit_exceeded`。
4. **不改造也不会坏**：面板什么都不做时，客户端收到明文，按现有流程工作。是否上线 CVD 完全由面板决定。

> ⚠️ 加密本身不是防护的核心，**真正抬高成本的是「设备槽位上限」+「对受保护 token 拒绝明文请求」这两条服务端策略**（见 §2、§11）。

---

## 1. 工作模型（务必先理解）

- **机会式（opportunistic）**：客户端会在可安全建立或复用设备密钥时自动尝试 CVD；服务端「支持就加密、不支持就明文」，两端都能正常工作。
- **公钥即设备身份**：不存在 device_id。同一设备（同一订阅 profile）每次更新都发送**同一个**持久公钥；面板据此识别设备、计数、可吊销。
- **私钥只在客户端本机 keychain**：面板永远只拿到公钥，永远不接触私钥。
- **向后兼容**：老客户端 / 浏览器 / curl 不带 `X-CVD-Pub`；面板需对「无公钥请求」单独决策（明文或拒绝，见 §11）。

---

## 2. 必须诚实的边界（先读，避免误用）

CVD 不是 DRM，请不要据此对外宣称「订阅无法被盗」。客观能力：

- **挡不住肯写代码的人**：协议公开，任何人可自己生成密钥对、注册一个设备槽位，照样解出明文。
- **一次解密 = 当前节点全泄露**：解密后的 YAML 含真实节点凭据（密码/UUID/IP），可直接使用。设备上限限制的是「持续获取更新」的设备数，**不是「一次性批量抓取」**。
- **挡不住账号持有者本人泄露**：合法设备正常解密后可手动复制明文。CVD 防的是「只拿到 token 的第三方」。
- **不防 MITM / 重放 / 投毒**：这些不在协议目标内，HTTPS 仍然必须开启。
- **加密的现实价值**：让「把订阅 URL 贴进浏览器/通用 curl 就抄到节点」的懒人路径失效，逼对方必须跑真正的协议代码。
- **设备槽位限额可被持有 token 的攻击者用来 DoS 真人**（刷满槽位把真实用户锁在外面）——必须配合新公钥注册频率限制（§11）。

---

## 3. 请求格式（客户端 → 面板）

客户端对远程订阅发起标准 `GET`，**仅新增以下请求头，不改 URL / query / 其它头**：

```http
GET /api/v1/client/subscribe?token=xxxxxxxx HTTP/1.1
Host: panel.example.com
X-CVD-Ver: 1
X-CVD-Pub: 8n7xxaMI-PlvyMurFN4etuMZNqUtg9lvru9vgRUAUxU
X-CVD-AEAD: 3
```

| 头 | 含义 | 格式 |
|----|------|------|
| `X-CVD-Ver` | 协议版本 | 十进制整数，当前恒为 `1` |
| `X-CVD-Pub` | 设备 X25519 公钥 | **base64url 无填充**（字母表 `A–Z a–z 0–9 - _`，无 `=`），解码后**恰好 32 字节** |
| `X-CVD-AEAD` | 客户端偏好的 AEAD | 十进制：`3`=ChaCha20-Poly1305，`2`=AES-256-GCM。**仅为偏好**；面板可忽略并自选（见 §6） |

要点：
- `X-CVD-Pub` 解码后必须是 32 字节，否则面板应视为非法 CVD 请求（按明文或拒绝处理）。
- 同一设备的公钥跨多次更新**保持不变**，因此「注册」是幂等的：`(token, pub)` 已存在就只刷新 `last_seen`。
- 客户端当前实现没有用户开关。新建 / 导入订阅会自动尝试 CVD；尚未注册的旧订阅会在**手动更新**时尝试注册；已有 `cvd_pub` 缓存的订阅会在后续更新中持续携带这三个头。
- 尚未注册的旧订阅在静默自动更新时不会主动创建密钥，以避免系统启动时触发 keychain 授权弹窗。keychain 不可用时，客户端也会跳过 CVD、按无 CVD 请求处理。

---

## 4. 服务端处理流程（每个带 `X-CVD-Pub` 的请求）

```
1. token   = 你现有的订阅鉴权流程解析出的 token / 用户
2. pubkey  = base64url_decode(X-CVD-Pub)        // 必须 32 字节，否则当作无 CVD 请求
3. 设备注册 / 限额检查（事务安全，见 §5）
     ├─ 已注册 或 注册成功 → 4
     └─ 超过设备上限       → 返回 403 device_limit_exceeded（见 §9）
4. yaml    = 生成该用户的订阅明文（你现有逻辑）
5. body    = HPKE_Seal(pubkey, yaml)            // 见 §6 §7
6. 返回 200 + X-CVD-Encrypted: 1 + X-CVD-AEAD: <实际AEAD> + body
```

对**不带** `X-CVD-Pub` 的请求：按 §11 的策略决定返回明文还是拒绝。

---

## 5. 设备注册与限额（数据库 + 并发安全）

### 5.1 表结构（参考）

```sql
CREATE TABLE cvd_devices (
    token_hash  CHAR(64)  NOT NULL,   -- sha256(subscription_token) 的十六进制；或直接用你的 user_id
    pub_key     CHAR(43)  NOT NULL,   -- X-CVD-Pub 原文（base64url-nopad，32 字节 → 43 字符）
    last_seen   TIMESTAMP NOT NULL,
    PRIMARY KEY (token_hash, pub_key)
);
CREATE INDEX idx_cvd_token ON cvd_devices (token_hash);
```

### 5.2 注册逻辑（必须事务安全，否则会超卖槽位）

```
BEGIN TRANSACTION
  key = (token_hash = sha256(token), pub_key = X-CVD-Pub 原文)

  row = SELECT * FROM cvd_devices WHERE token_hash=? AND pub_key=? FOR UPDATE
  IF row 存在:
      UPDATE last_seen = now()
      COMMIT
      → 允许，用 pub_key 加密返回
  ELSE:
      cnt = SELECT COUNT(*) FROM cvd_devices WHERE token_hash=?    -- 同一事务内
      IF cnt >= 设备上限 N:
          ROLLBACK
          → 403 device_limit_exceeded （可带 X-CVD-Max-Devices: N）
      ELSE:
          INSERT (token_hash, pub_key, last_seen=now())
          COMMIT
          → 允许，用 pub_key 加密返回
```

> **并发不超卖**：`COUNT` 与 `INSERT` 之间存在竞态。必须把「计数 + 插入」放在同一事务（如 `FOR UPDATE` 行锁），或用数据库唯一约束 + token 维度计数兜底。仅靠应用层「先查后插」会被并发突破上限。
> **幂等**：`(token_hash, pub_key)` 唯一，同一公钥重复请求不会重复占槽。

### 5.3 槽位回收（强烈建议）

客户端的私钥只在本机 keychain，**不随备份导出**。用户换机 / 重装系统 / 清空 keychain 后，会用**新公钥**重注册一个新槽位（旧槽位变成死槽）。因此：

- 建议按 `last_seen` 设过期回收（例如 30/60 天未出现即释放），否则真实用户长期使用会被自己的换机历史塞满槽位。
- 面板控制台应提供「查看/解绑设备」入口，给用户自助清理的能力。

---

## 6. 加密响应格式（面板 → 客户端）

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Cache-Control: no-store
X-CVD-Encrypted: 1
X-CVD-AEAD: 3

I9RQxCOpo0QI30wTsl2wCrNqByOLNJr1baCXumWU9Sh...（base64url-nopad 文本）
```

- **`X-CVD-Encrypted: 1`**：表示这是 CVD 密文。**只有在 body 确实是合法密文时才设置它**（否则客户端会报错，且不回退明文——见 §9 §10）。
- **`X-CVD-AEAD`**：填你**实际使用**的 AEAD（`2` 或 `3`）。客户端用**响应头里这个值**解密，而不是它请求时的偏好。所以你可以无视客户端偏好自选其一，客户端两种都支持。
- **Body** = `base64url_nopad( enc || ciphertext )`：
  - `enc`：HPKE 封装的临时公钥（X25519，**32 字节**）。
  - `ciphertext`：AEAD 密文，**含 16 字节 tag**。
  - 解码后长度必须 **≥ 48** 字节（32 + ≥16）。
- **必须 base64url 文本**：客户端把 HTTP body 当**文本**读取后再 base64url 解码。**不要直接发二进制**，会被字符集解码破坏。
- **不可跨设备缓存**：每个设备的 `enc` 是临时随机的、响应各不相同。务必 `Cache-Control: no-store`（或按设备公钥 Vary），不要让 CDN 缓存加密响应。

---

## 7. HPKE 参数（必须逐项完全一致）

实现按 **RFC 9180 Single-Shot `SealBase`**：

| 项 | 值 |
|----|----|
| Mode | **Base**（`mode_base = 0x00`，无 PSK、无发送方认证） |
| KEM | **DHKEM(X25519, HKDF-SHA256)**，`kem_id = 0x0020` |
| KDF | **HKDF-SHA256**，`kdf_id = 0x0001` |
| AEAD | **ChaCha20-Poly1305** `0x0003`（推荐）**或** **AES-256-GCM** `0x0002` |
| `info` | ASCII 字节串 **`cvd-v1`**（6 字节：`63 76 64 2d 76 31`，无结尾 0） |
| `aad` | **空**（长度 0） |
| `psk` / `psk_id` | 无（Base 模式） |
| 输出 | `(enc, ciphertext) = SealBase(pkR, info, aad="", pt=订阅YAML字节)` |

`pkR` = `X-CVD-Pub` 解码出的 32 字节原始 X25519 公钥。`Nk`（key）=32、`Nn`（nonce）=12、`Nenc`=32、`Nsecret`=32。

> 这是 RFC 9180 标准套件，主流库都直接支持，**不要自定义任何环节**（标签、info、AAD、序列化）。务必用 §14 的 KAT 验证你的实现确实与客户端互通。

---

## 8. 明文响应（不支持 / 不强制 CVD 时）

```http
HTTP/1.1 200 OK
（没有 X-CVD-Encrypted 头）

<明文订阅 YAML>
```

客户端检测到无 `X-CVD-Encrypted` 头即按「订阅服务不支持 CVD」处理，使用明文。未改造的面板天然就是这个行为。

---

## 9. 错误响应

| 场景 | 状态码 | 响应头 | 客户端行为 |
|------|--------|--------|-----------|
| 设备数超限 | `403` | `X-CVD-Error: device_limit_exceeded`（可选 `X-CVD-Max-Devices: N`） | 提示用户「前往订阅服务控制台解绑旧设备后重试」，**不回退明文** |
| 其它任意非 2xx | 4xx/5xx | 任意 | 视为本次更新失败，**不回退明文** |
| 设了 `X-CVD-Encrypted: 1` 但 body 非法 / 缺 `X-CVD-AEAD` / 解码后 < 48 字节 | 200 | — | 视为错误，**不回退明文** |

> 关键：**只在能正确产出合法密文时才设 `X-CVD-Encrypted: 1`**。一旦设了却给不出合法密文，客户端这次更新会直接失败（不会悄悄退回明文）。无法加密时，要么返回纯明文（不带该头），要么返回明确错误状态码。

---

## 10. 客户端校验规则清单（你的响应必须满足）

客户端按以下规则解析响应（顺序即优先级）：

1. `403` 且 `X-CVD-Error` 去空白后等于 `device_limit_exceeded` → 设备超限错误。
2. 任意非 2xx（除上一条）→ 错误。
3. 2xx 且 `X-CVD-Encrypted` 去空白后等于字符串 `1`：
   - 读 `X-CVD-AEAD`，去空白后必须是 `2` 或 `3`，否则错误；
   - body 去空白后做 base64url-nopad 解码，失败则错误；
   - 解码长度 < 48 则错误；
   - 否则取前 32 字节为 `enc`、其余为 `ciphertext`，用响应头的 AEAD + `info="cvd-v1"` + 空 AAD 做 HPKE-Open。
4. 2xx 且无 `X-CVD-Encrypted` 头 → 明文。

对照实现：`parse_response` / `hpke_open`（`src-tauri/src/cvd/mod.rs`）。

---

## 11. 强制策略（真正产生防护价值，由面板决定）

协议本身**不强制**任何东西；只有加上以下策略才真正抬高获取者成本：

1. **对受保护 token 拒绝明文请求**：对启用 CVD 的 token，拒绝**不带** `X-CVD-Pub`（或带了但你不认）的请求——否则攻击者只要不发这个头就拿到明文，加密形同虚设。这是「成本」的来源。
2. **设备上限 N**：按套餐设定（如 3/5）。
3. **按 token / 源 IP 限制「新公钥注册」频率**：防止持有 token 的攻击者刷满槽位，把真实用户锁在外面（§2 提到的 DoS）。
4. **`last_seen` 回收死槽**（§5.3）。

> 仅实现 §3–§9 而不加策略 1，CVD 只能挡住懒人脚本；要把成本真正抬起来，策略 1 是必须的，且其副作用（误伤老客户端/其它工具）需你自己权衡灰度。

---

## 12. 部署注意

- **HTTPS 必须保留**：CVD 不替代 TLS，不防 MITM / 重放。
- **CDN / WAF / 反向代理必须透传 `X-CVD-*` 请求头**到处理订阅的后端，**不要在边缘层剥离**，否则后端永远收不到公钥。
- **加密响应必须是 base64url 文本** + `Cache-Control: no-store`（每设备不同，禁止跨设备缓存）。
- **同时兼容无 CVD 请求**：更新后的客户端会在新建 / 导入或手动更新后逐步启用 `X-CVD-*`；老客户端、其它工具，以及尚未注册的静默更新仍可能不带。后端两种都要能处理。
- **版本**：当前只有 `X-CVD-Ver: 1`。若未来见到更高且你不支持的版本，按明文处理（不要用不兼容方案加密）。

---

## 13. 服务端参考实现

### 13.1 算法（语言无关，等价于 RFC 9180 `SealBase`）

```
# pkR = 32 字节接收方公钥; info = "cvd-v1"; aad = ""; pt = 订阅 YAML 字节
(skE, pkE) = X25519_GenerateKeyPair()
dh         = X25519(skE, pkR)                 # 32 字节
enc        = pkE                              # 32 字节
shared     = DHKEM_ExtractAndExpand(dh, enc || pkR)         # RFC 9180 §4.1，HKDF-SHA256
(key, base_nonce) = KeySchedule_Base(shared, info)          # RFC 9180 §5.1
ciphertext = AEAD_Seal(key, base_nonce, aad="", pt)         # seq=0，nonce=base_nonce
body       = base64url_nopad(enc || ciphertext)
```

> 各步骤的 `LabeledExtract/LabeledExpand` 标签（`"HPKE-v1"`、`suite_id`、`"eae_prk"`、`"shared_secret"`、`"secret"`、`"key"`、`"base_nonce"` 等）严格按 RFC 9180。**强烈建议直接用成熟库而非手写**，并用 §14 的 KAT 验证。

### 13.2 推荐库

| 语言 | 库 | 说明 |
|------|----|------|
| Go | `github.com/cloudflare/circl/hpke` | 成熟、API 直观，推荐 |
| Node.js / TS | `@hpke/core`（hpke-js） | 维护良好 |
| Python | `pyhpke` | 直接支持本套件 |
| Rust | `hpke` / `rust-hpke` | 客户端即用此 |
| PHP | **无成熟原生库** | 见 §13.4 |

### 13.3 Go 示例（CIRCL）

```go
import (
    "crypto/rand"
    "encoding/base64"
    "github.com/cloudflare/circl/hpke"
)

func sealForDevice(pubB64url string, yaml []byte) (body string, aead string, err error) {
    suite := hpke.NewSuite(
        hpke.KEM_X25519_HKDF_SHA256,
        hpke.KDF_HKDF_SHA256,
        hpke.AEAD_ChaCha20Poly1305, // 对应 X-CVD-AEAD: 3
    )
    pkBytes, err := base64.RawURLEncoding.DecodeString(pubB64url) // 32 字节
    if err != nil { return "", "", err }
    pkR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(pkBytes)
    if err != nil { return "", "", err }

    sender, err := suite.NewSender(pkR, []byte("cvd-v1")) // info
    if err != nil { return "", "", err }
    enc, sealer, err := sender.Setup(rand.Reader)
    if err != nil { return "", "", err }
    ct, err := sealer.Seal(yaml, nil) // aad = nil（空）
    if err != nil { return "", "", err }

    payload := append(append([]byte{}, enc...), ct...) // enc(32) || ciphertext
    return base64.RawURLEncoding.EncodeToString(payload), "3", nil
}
// 响应：200 + X-CVD-Encrypted: 1 + X-CVD-AEAD: <aead> + body
```

### 13.4 Node.js 示例（hpke-js，亦可作为 PHP 面板的 sidecar）

```js
import { CipherSuite, KemId, KdfId, AeadId } from "@hpke/core";

async function sealForDevice(pubB64url, yamlBytes) {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305, // X-CVD-AEAD: 3
  });
  const raw = Buffer.from(pubB64url, "base64url");            // 32 字节
  const pkR = await suite.kem.importKey("raw", raw, true);    // 公钥
  const sender = await suite.createSenderContext({
    recipientPublicKey: pkR,
    info: new TextEncoder().encode("cvd-v1"),
  });
  const ct = new Uint8Array(await sender.seal(yamlBytes));    // aad 默认空
  const enc = new Uint8Array(sender.enc);                     // 32 字节
  const body = new Uint8Array(enc.length + ct.length);
  body.set(enc, 0); body.set(ct, enc.length);
  return Buffer.from(body).toString("base64url");             // enc || ct
}
```

> 库的 API 在不同版本可能略有差异；**以 §14 的 KAT 跑通为准**。

### 13.5 PHP 面板（V2board / Xboard 等）

PHP 没有成熟的 HPKE 原生库。两条路：

- **推荐：起一个 Go / Node 的 sidecar**（如 §13.3 / §13.4 包成一个内网 HTTP/CLI 服务），PHP 把 `pubkey + yaml` 传进去拿回 `body`。最省事、最不易出错。
- **原生实现**：基于 libsodium（PHP `sodium_*`）按 RFC 9180 Base 模式手写：
  - X25519：`sodium_crypto_scalarmult($skE, $pkR)`；临时密钥对 `sodium_crypto_box_keypair` 取其 X25519 部分，或直接 `sodium_crypto_kx_*` 的底层 scalarmult。
  - HKDF-SHA256 的 Extract/Expand：用 `hash_hmac('sha256', ...)` 自行实现 RFC 5869，并套上 RFC 9180 的 `LabeledExtract/LabeledExpand`（标签前缀 `"HPKE-v1"` + `suite_id`）。
  - AEAD：`sodium_crypto_aead_chacha20poly1305_ietf_encrypt`（对应 `3`）或 `openssl_encrypt('aes-256-gcm', ...)`（对应 `2`）。
  - **务必用 §14 KAT 验证**后再上线；手写 KDF 标签极易出错。

---

## 14. 互操作测试向量（KAT）

下列向量由 **Clash Verge 客户端的真实加解密代码**产出，套件为 `DHKEM(X25519,HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305`，`info = "cvd-v1"`，`aad = ""`。

> ⚠️ 仅用于测试，**切勿在生产中使用此密钥对**。

```
# 接收方（设备）X25519 私钥，base64url-nopad（32 字节）
RECIPIENT_PRIV = wJnpUjoQOd2ih2Ppz4FvpHZKknrif6m0yxo1ZXOAijY

# 对应公钥，即客户端会发来的 X-CVD-Pub，base64url-nopad（32 字节）
RECIPIENT_PUB  = 8n7xxaMI-PlvyMurFN4etuMZNqUtg9lvru9vgRUAUxU

AEAD = 3   (ChaCha20-Poly1305)
INFO = "cvd-v1"

# 一条合法密文 body = base64url-nopad(enc(32) || ciphertext)
BODY = I9RQxCOpo0QI30wTsl2wCrNqByOLNJr1baCXumWU9ShlRKEQKchHMcSqWqm9XrUqkCbVIS0Ye1bzB3trh8jQTWM-XBpnx2IOqIxxrywhC2Zb2iha75U1gCwtuzeXOzqDtha4Ktr7eE1edJvjvMShPvHvFjyUE0alwDopvlf-w2A4PjWC7LO-AQnWnnzPzcsgu2dIJDtdXPU

# BODY 解密后应得到的明文（注意结尾换行）：
PLAINTEXT =
proxies:
  - {name: demo, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: s3cret}
```

### 怎么用它验证你的实现

1. **验证套件互通（最关键）**：用你的 HPKE 库，以 `RECIPIENT_PRIV` 对 `BODY`（取前 32 字节为 `enc`、其余为 `ciphertext`）做 **OpenBase**（同套件、`info="cvd-v1"`、`aad=""`）。结果必须**逐字节等于** `PLAINTEXT`。
   - 这条通过 ⇒ 你的库与客户端套件参数完全一致。
2. **验证你的 seal 路径**：用你的实现对 `RECIPIENT_PUB` 加密 `PLAINTEXT`，再用 `RECIPIENT_PRIV` 解密，应能往返得到 `PLAINTEXT`。（注意：`enc` 含随机临时密钥，你产出的 `BODY` 不会与上面的逐字节相同，这是正常的。）
3. **验证公钥派生**：`RECIPIENT_PRIV` 的 X25519 公钥应等于 `RECIPIENT_PUB`。
4. （可选）参照 RFC 9180 Appendix A 的标准 KAT 验证底层原语。

---

## 15. 端到端示例

**① 客户端请求**

```http
GET /api/v1/client/subscribe?token=USER_TOKEN HTTP/1.1
Host: panel.example.com
X-CVD-Ver: 1
X-CVD-Pub: 8n7xxaMI-PlvyMurFN4etuMZNqUtg9lvru9vgRUAUxU
X-CVD-AEAD: 3
User-Agent: clash-verge/vX.Y.Z
```

**② 加密响应（已注册 / 注册成功）**

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Cache-Control: no-store
X-CVD-Encrypted: 1
X-CVD-AEAD: 3

I9RQxCOpo0QI30wTsl2wCrNqByOLNJr1baCXumWU9Sh...（base64url-nopad）
```

**③ 设备超限**

```http
HTTP/1.1 403 Forbidden
X-CVD-Error: device_limit_exceeded
X-CVD-Max-Devices: 3
```

**④ 明文回退（面板未支持 / 未对该 token 启用 CVD）**

```http
HTTP/1.1 200 OK
Content-Type: text/yaml

proxies:
  - { ... 明文节点 ... }
```

---

## 16. 实现核对清单（Checklist）

- [ ] CDN/WAF/反代已透传 `X-CVD-*` 请求头到后端
- [ ] 解析 `X-CVD-Pub` → base64url-nopad → 校验 32 字节
- [ ] `(token_hash, pub_key)` 设备表 + **事务安全**的注册/计数/限额
- [ ] HPKE `SealBase`：KEM `0x0020` / KDF `0x0001` / AEAD `0x0003`或`0x0002` / `info="cvd-v1"` / `aad=""`
- [ ] 响应：`200` + `X-CVD-Encrypted: 1` + `X-CVD-AEAD: <实际值>` + `Cache-Control: no-store`
- [ ] body = `base64url_nopad(enc(32) || ciphertext)`，**文本**返回
- [ ] 超限 → `403` + `X-CVD-Error: device_limit_exceeded`
- [ ] 无法加密时绝不设 `X-CVD-Encrypted: 1`（改返回明文或错误码）
- [ ] **用 §14 KAT 跑通 Open**，确认与客户端互通
- [ ] （策略）对受保护 token 拒绝明文请求；限制新公钥注册频率；`last_seen` 回收死槽
- [ ] 控制台提供「查看/解绑设备」入口

---

*本文随客户端实现演进；协议常量以仓库 `src-tauri/src/cvd/mod.rs` 与 §14 KAT 为准。*

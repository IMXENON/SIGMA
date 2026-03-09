# README.md

本项目实现了一个基于公钥基础设施 (PKI) 和TCP可靠连接的 Sign-and-MAC 密钥交换协议。

### 1. 协议概述

该实现结合了数字签名和消息认证码 (MAC) 技术，在公钥基础设施支持下实现安全密钥交换。

### 2. 客户端建立连接流程

1. **初始化阶段**
    
    客户端启动，准备建立安全连接。
    
2. **CA 认证申请**
    
    模拟 CA 节点，客户端在强安全信道下向 CA 节点申请证书。CA 私钥和公钥为硬编码。
    
3. **开启监听**
    
    完成认证后，客户端开始监听来自其他节点的连接请求。
    
4. **主动连接**
    
    节点可主动向已认证节点发起连接。
    
5. **握手协商**
    
    双方执行完整 Sign-and-MAC 握手协议。
    
6. **密钥建立**
    
    握手成功后，双方获得共享 session key，可进行加密通信。
    
7. **通信**
    
    在双方通信期间，session key会随着会话在新的密钥交换handshake基础上不断更新，从而达到协议的向前/向后安全。
    

### 3. 安全特性

本项目在安全设计上考虑了多方面的威胁模型。需要注意的是：

- **PKI 与 CA 交互假设安全**：项目中模拟了客户端节点与 CA 的交互，CA 公钥等字段硬编码以演示流程。在实际应用中，需要保证与 PKI 的通信信道安全，防止篡改或监听。
- **底层加密依赖**：项目使用 Go 的 `crypto/boringSSL` 库提供的密码学原语，并结合 **Sign-and-MAC** 握手协议实现安全通信。

下面从信息安全和软件实现两个方向说明本项目提供的安全特性。

#### 3.1. 信息暴露与防篡改

1. **异步向前/向后安全 (Forward & Backward Security)**
    - 每轮握手由连接发起方负责触发。
    - 最小触发条件：
        - 一方在当前 session 中至少发送了一条消息
        - 另一方至少发送了 `txCountLimit` 条消息
    - 通过这种机制，即使某个 session 的密钥泄露，也无法推算历史或未来 session 的密钥。
2. **最小暴露 Header**
    - 每条消息都会进行随机长度填充
    - 暴露在外的仅有 epoch 信息
    - 这样可以减少网络流量分析或被动监听带来的信息泄露。
3. **消息 AEAD 加密**
    - 每条消息与其 Header 使用不同的 session key 分别加密
    - 提供消息机密性、完整性和认证

#### 3.2. 软件实现安全

1. **敏感退出原则 (Fail-Safe on Tampering)**
    - 当 AEAD 认证或解密失败时，说明消息可能被篡改
    - 节点会立即主动关闭连接，并通过 TCP FIN 通知对方
    - 避免被攻击方利用非法消息破坏会话状态
2. **长期防重放 (Long-Term Replay Protection)**
    - 假设攻击者在 epoch X 获取了 Alice → Bob 的消息
    - 若在未来轮次再次发送该消息，由于对应 epoch 的 session key 已被移出缓存
    - 接收方会遇到解密/认证失败，从而防止重放攻击
    - **注意**：如果 epoch key 仍在内存中，攻击者理论上可能进行重放攻击

### 4. 使用方法

本程序支持两种运行模式：

- **CA 模式**：模拟证书颁发机构（Certificate Authority）
- **Client 模式**：节点客户端，用于建立安全连接并发送加密消息

程序通过命令行参数控制运行模式。

---

#### 4.1. 启动 CA 服务器

CA 节点负责签发证书，客户端启动时会向 CA 申请证书。

```
go run main.go -mode CA -port 8081
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-mode` | `client` | 运行模式 (`CA` 或 `client`) |
| `-port` | `8080` | 服务器监听端口 |

启动后，CA 将监听指定端口并处理客户端证书请求。

---

#### 4.2. 启动客户端节点

客户端节点会：

1. 向 CA 申请证书
2. 初始化本地身份
3. 开启 TCP 监听
4. 启动命令行交互界面

示例：

```
go run main.go -mode client-port=8082-sub Alice.com-caport=8081
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-mode` | `client` | 运行模式 |
| `-port` | `8080` | 当前节点监听端口 |
| `-sub` | `example.com` | 节点 Subject（身份标识） |
| `-caport` | `8081` | CA 服务器端口 |

例如启动两个节点：

```
# Node Alice
go run main.go -mode client -port 8082 -sub Alice.com -caport 8081

# Node Bob
go run main.go -mode client -port 8083 -sub Bob.com -caport 8081
```

---

#### 4.3. 客户端命令

客户端启动后会进入交互命令模式：

```
>
```

支持以下命令。

---

##### 4.3.1 连接到其他节点

建立 TCP 连接并执行安全握手。

```
connect <host:port>
```

示例：

```
connect localhost:8083
```

连接流程：

1. 创建 TCP 连接
2. 执行 `HandshakeAsInitiator`
3. 验证证书
4. 建立 session key
5. 完成 secure connection

---

##### 4.3.2 发送加密消息

```
send <subject> <message>
```

示例：

```
send Bob.com Hello Bob!
```

流程：

1. 根据 subject 查找连接
2. 使用 session key 进行 AEAD 加密
3. 发送消息

---

##### 4.3.3 关闭连接

主动关闭与某节点的连接。

```
close <subject>
```

示例：

```
close Bob.com
```

---

##### 4.3.4 查看节点状态

打印当前节点连接信息。

```
print peers
```

输出示例：

```
Peers: map[Bob.com:0xc0001a2000]
```

---

##### 4.3.5 退出程序

```
exit
```

---

### 4.4 示例运行流程

启动 CA：

```
go run main.go-mode=CA-port=8081
```

启动两个客户端：

```
go run main.go-mode=client-port=8082-sub Alice.com-caport=8081
go run main.go-mode=client-port=8083-sub Bob.com-caport=8081
```

在 Alice 节点输入：

```
connect localhost:8083
```

握手成功后发送消息：

```
send Bob.com Hello Bob!
```

Bob 节点将接收到并解密消息。

## 5. 测试

本项目通过 单元测试 (Unit Tests)、安全测试 (Security Tests) 和 压力测试 (Stress Tests) 三类测试来验证协议实现的正确性与安全性。

测试代码主要位于以下两个模块：

```
connection/
node/
```

运行全部测试：

`go test ./... -v`

### 5.1. 加密通信单元测试
#### 5.1.1. 加密通信可用性测试

该部分测试 SecureConn 的基本加密通信功能，确保发送端和接收端能够正确完成加密与解密。

主要测试内容：
- WriteEnc() 与 ReadEnc() 的完整通信流程
- 不同类型消息的加密与解密
- Header 字段解析正确
- TxCount 是否按顺序递增

测试示例：

- TestWriteReadRoundTrip
- TestHeaderFields
- TestTxCountIncrease

这些测试验证协议在正常情况下可以稳定完成安全通信。

#### 5.1.2. 消息完整性单元测试

该部分测试协议是否能够检测数据被篡改的情况。

主要测试：

- TestHeaderTamper
- TestPayloadTamper

测试方法：

- 修改 Header 字节
- 修改加密 Payload

预期结果：

解密阶段的认证失败，连接拒绝该消息。

这验证了 AEAD 加密能够提供 消息完整性保护。

#### 5.1.3. 网络异常单元测试

该部分测试协议在网络异常情况下的行为，例如数据截断或连接提前关闭。

主要测试：

- TestTruncatedFrame
- TestRealNetworkTruncation
- TestReadEncWithNetworkTruncation

测试场景包括：

- 数据帧被截断
- TCP 连接提前关闭
- ReadFull 读取不完整数据

预期行为：

协议能够检测异常并返回错误，而不会继续解析损坏的数据。

### 5.2. 节点通信测试
#### 5.2.1. Refresh Handshake 测试
TestFullRefreshCycle
该测试验证 密钥刷新机制是否正确触发。
测试流程：
1. Alice 与 Bob 建立初始握手
2. 双方发送多轮加密消息
3. 当消息数量达到阈值时触发 refresh handshake
4. 新密钥建立后继续通信
最终检查：epoch > 0。如果 epoch 发生增加，说明 refresh handshake 成功。

#### 5.2.2. 随机通信测试
TestRandomTimeMessaging

该测试模拟 随机消息发送场景。

测试流程：
1. 在大量循环中随机选择发送方
2. Alice 或 Bob 随机发送消息
3. 每隔一段时间打印当前 epoch

示例输出：
`Fuzz progress: i=1000, epochA=1, epochB=1`

测试目标：

验证随机通信不会导致协议错误

验证 refresh handshake 能在高频通信下正常触发


#### 5.2.3. Trace 可视化通信测试

`TestAsymmetricMessagingVisualRandom`

该测试在高并发随机通信的基础上，对节点之间的消息传输进行 **通信轨迹记录（trace）**，并导出为可视化序列图。

测试流程：

1. Alice 与 Bob 建立初始安全连接
2. 双方随机发送大量消息
3. 每条消息记录以下信息：
   - 发送节点
   - 接收节点
   - 当前 Epoch
   - 当前 TxCount
4. 将记录的通信事件导出为 HTML 可视化文件

记录的数据结构示例：

```
TraceEvent {
    Time
    From
    To
    Epoch
    TxCount
}
```

为了避免内存无限增长，测试使用 **固定容量的 ring buffer** 保存最近的通信事件。

测试完成后，系统会生成通信轨迹文件：

```
trace/flow_trace.html
```

该文件使用 **Mermaid sequence diagram** 展示节点之间的通信顺序，例如：

```
Alice->>Bob: epoch=1 tx=5
Bob->>Alice: epoch=1 tx=6
Alice->>Bob: epoch=2 tx=0
```

打开方式：

```
open trace/flow_trace.html
```

或直接使用浏览器打开该文件，即可查看完整的通信序列图。

测试目标：

- 观察高并发随机通信下的消息流
- 验证 Epoch 与 TxCount 的演化过程
- 辅助调试 refresh handshake 和消息顺序问题


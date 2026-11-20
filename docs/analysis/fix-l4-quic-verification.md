# fix/l4-quic 分支验证报告

分析基线：`master` = `1353123`；分支 `fix/l4-quic` = `daea6de`（含 pull 后新增的 `daea6de`）。
分析时间：2026-11-20。工作区干净，相关包测试全部通过。

## 结论（先说结果）

**两个问题都只是“部分缓解”，没有完全解决。**

| 问题 | 现状 | 判断 |
|---|---|---|
| ① 路由表有状态：首次匹配错后，新 TLS/QUIC init 被忽略 | 新增了基于包特征的启发式“杀旧 flow”逻辑；覆盖“DCID 变化 + 先出现 1-RTT 短包”场景，但存在多个确定漏检和误杀窗口 | **部分修复**，不是根因修复 |
| ② 原版 UDP proxy 断流、长时间不恢复、需重启 Caddy | 修复了 standalone `layer4` app 的一条读错误致死路径和 UDP half-close 挂死；但 Caddy HTTP/3 的 `caddy.packetconns.layer4` 包装路径没有同步修复，且重启逻辑实际上很难触发 | **部分修复**，特定部署形态下仍会复发 |

另外，`b491b35` 的 ALPN 快速失败没有任何新测试，且 `alpnMismatch` 存在跨 goroutine 无同步访问的风险；`84b1e0b` 新增的 PROXY protocol packetconn wrapper 与问题①②的修复没有直接关系，且其生效依赖 wrapper 顺序。

---

## 1. 分支提交清单

| 提交 | 内容 |
|---|---|
| `fd44f86` | 在 `packetConn` 读循环中识别 QUIC Initial / DTLS ClientHello，满足条件时关闭旧 split flow；`QUICAcceptTimeout` 100ms → 1s |
| `84b1e0b` | 新增 `caddy.packetconns.proxy_protocol` UDP/QUIC wrapper |
| `b491b35` | `MatchQUIC` 用 `GetConfigForClient` 在 ALPN 不匹配时快速失败 |
| `daea6de` | 新增 `resilientPacketConn` 吞掉瞬态读错误、splitter 重启循环、deadline 加锁、UDP half-close 时直接关闭 downstream |

`master...HEAD` 共 8 个文件、+653/-36 行。

---

## 2. 问题①：错误匹配后新 init 包被忽略

### 修复机制

`layer4/server.go:242-330`：每个 UDP flow 的喂包 goroutine 维护：

- `initialDCID` / `firstInitialTime`：第一个 QUIC Initial 的 DCID 与时间；
- `hasData`：见过 QUIC 短头包（视为 1-RTT 数据）；
- `writtenPackets`：调用 `packetConn.Write` 的次数。

后续包满足任一条件就 `pc.PacketConn.Close()`，让 hybrid splitter 结束旧 flow，期待客户端重传后建立新 flow 重新匹配：

- DCID 不同；
- 已见过短头包；
- `time.Since(firstInitialTime) > 800ms`（无条件）；
- `writtenPackets == 0 && time.Since(firstInitialTime) > 300ms`；
- DTLS ClientHello 且（`hasData` 或上游 300ms 无回应）。

### 验证结果

✅ **已验证有效**：原测试和新增测试 `TestServePacketNewQUICInitialResetsFlow`（`layer4/server_udp_test.go:637-711`）证明“短头包 + 不同 DCID 的 Initial”会结束旧 handler，重传后新 handler 启动。

❌ **已验证漏检 1：同 DCID 重传 + 上游已回包，不会重置。** 临时测试（验证后已删除）构造 1200 字节 v1 Initial（DCID=`SAME`），handler 立即回写 `garbage`，100ms 后重传同一 Initial：

```
handler count after same-DCID retransmit with upstream bytes = 1
```

原因：`isDifferentDCID=false`、`hasData=false`、`writtenPackets>0` 使 300ms 规则失效、距首个包仅 100ms 使 800ms 规则失效。也就是说，只要误匹配的上游“回了任意字节”，客户端在 800ms 内的重传全部被旧 handler 吞掉。

❌ **已验证漏检 2：QUIC v2 Initial 完全识别不到。** `parseQUICInitialDCID` 只接受 `(b[0]&0xf0)==0xc0`；quic-go v0.64.1 的 v2 Initial 首字节为 `0xd0`（`internal/wire/header.go:203-213`）。临时测试确认：

```
QUIC v2 Initial detected = false
```

⚠️ **误杀风险：800ms 规则是无条件的。** 只要第一个 Initial 之后 800ms 再来 Initial，即使上游正常响应、握手正常推进，也会被强制杀 flow。配合 `QUICAcceptTimeout` 被调到 1s，慢网络/多轮 Retry 的握手可能反复被重置，反而制造断流。

⚠️ **丢包风险**：触发重置时，那个“新 init 包”被直接丢弃并归还 buffer，不转发给上游。恢复完全依赖客户端重传；DTLS 或只发一次 ClientHello 的实现会卡到 idle timeout（默认 30s）。

⚠️ **封装风险**：检测读的是 hybrid split conn 的裸包字节。若 `proxy_protocol` wrapper 在 `layer4` wrapper 之外（配置顺序反了），首字节是 PROXY v2 前缀，QUIC/DTLS 检测全部失效。正确顺序必须是 `proxy_protocol` 在前、`layer4` 在后（Caddy `ListenQUIC` 按列表顺序 `WrapPacketConn`，见 caddy `listeners.go:455-460`）。

⚠️ **DTLS 判断粗糙**：`isDTLSClientHello` 用 `b[0]==22 && b[1]==0xfe && b[13]==1`；首个 ClientHello 就把 `hasData` 置 true，因此第二个 ClientHello 必然杀 flow。对正常 DTLS 重传是“可用但粗暴”，且没有 DCID 概念，无法区分“新会话”和“重传”。

⚠️ `writtenPackets` 只在 `packetConn.Write` 计数；直接对底层调用 `WriteTo` 的 handler 不会计数，可能误触发 `upstreamSilent` 重置。

**小结**：问题①被从“永久卡死”降级为“多数 QUIC v1 场景可在一次重传后恢复”，但**不是完全解决**，且有新的误杀窗口。

---

## 3. 问题②：UDP proxy 断流且不恢复

### 3.1 已修复的部分

**half-close 挂死（真实根因之一）**：原 `modules/l4proxy/proxy.go` 在上游全部结束后执行 `closeWrite(down.Conn)`；UDP 的 `packetConn` 没有 `CloseWrite`，返回 false，但原代码仍继续 `downReader.arm()` 并阻塞等待 `<-downConnClosedCh`。`HalfCloseTimeout` 默认 0 时 `arm()` 不生效，于是该 flow 永久挂住，后续包继续送给死 handler → 断流。

`daea6de` 改为：

```go
if !closeWrite(down.Conn) {
    _ = down.Close()
} else {
    downReader.arm()
}
```

这是正确的 UDP 语义。新增测试 `TestHandleUDPUpstreamEOFClosesDownstream` 用 `net.Pipe` 模拟非 CloseWriter downstream，2s 内必须返回，验证了该分支。**这部分修复成立。**

**瞬态读错误打死 listener（另一真实根因）**：hybrid `splitter.readLoop` 遇到底层 `ReadFrom` 错误调用 `s.fail(err)`，进而 `stop` 并让 `AcceptSplit` 返回包装了 `net.ErrClosed` 的 `splitStoppedError`；`Server.servePacket` 收到后 `return err`，Caddy 不会自动重建该 UDP 监听 → 必须重启。

`daea6de` 的 `resilientPacketConn.ReadFrom`（`layer4/server.go:106-147`）把非 closed / 非 timeout 错误记录后重试，避免错误传给 hybrid。临时测试注入一次 `ECONNREFUSED` 后再正常发包：

```
TestVerifyResilientReadFromRetriesTransient: PASS
```

**这部分机制本身成立。**

### 3.2 仍然存在的缺口

❌ **`caddy.packetconns.layer4` 路径完全没修。** `layer4/packetconn.go:68-91` 的 `WrapPacketConn` 仍然直接：

```go
ln := hybrid.Split(hybrid.FakeClosePacketConn(pc, nil), ...)
go pcw.serve(ln)
```

没有 `resilientPacketConn`，没有重启循环，`pcw.serve`（`layer4/packetconn.go:94-116`）遇 `AcceptSplit` 错误直接 `return`。而这条路径正是 Caddy HTTP/3 + layer4 共端口的现代集成方式（`docs/examples/combining_apps.md`、`integration/packetconn_test.go`）。**如果生产配置用的是 `packet_conn_wrappers { layer4 { ... } }`，问题②的“需要重启 Caddy”依旧会出现。**

❌ **新增的 splitter 重启循环基本不可达。** 新代码在 `AcceptSplit` 出错时，只有 `!rpc.isClosed() && !errors.Is(err, net.ErrClosed)` 才重建 splitter；但 hybrid 的 `fail()` 产生的 `splitStoppedError` 明确 `Unwrap` 出 `net.ErrClosed`（hybrid `split.go:567-572`），所以任何真正的底层失败都会走 `return err`。自动恢复实际只覆盖极少数非 closed 的 Accept 错误，**不能把它当作 self-healing 保证**。

⚠️ **无限重试无退避**。`resilientPacketConn.ReadFrom` 把所有“非 closed/非 timeout”错误都当瞬态并立即 `continue`。若遇到永久错误（如 fd 失效、EINVAL、权限问题），会变成 CPU 空转，且 `servePacket` 永不返回，Caddy shutdown 会卡住。建议加连续错误上限/退避，并将明确不可恢复错误放行。

⚠️ **写路径未纳入**，但检查 hybrid `split_write.go:113-129` 后确认：除 `net.ErrClosed`/`io.ErrClosedPipe` 外的写错误只是计数并上报 `ErrorFunc`，不会停 splitter，所以这不是当前缺口。

---

## 4. `b491b35`：ALPN 快速失败

- 机制：`tlsConf.GetConfigForClient` 检查 `ClientHelloInfo.SupportedProtos`，不匹配则写 `alpnMismatch=true` 并返回错误；`Match()` 在 `Accept` 出错后据此返回 `(false, nil)` 而不是 `ErrConsumedAllPrefetchedBytes`，让路由立即 fall through。
- **没有任何新测试**：`modules/l4quic/matcher_test.go` 只改了 `Test_MatchQUIC_DeadlineReturnsNotMatched` 里临时把 timeout 设回 100ms；没有 ALPN mismatch 用例。
- **竞态风险**：`alpnMismatch` 是普通 `bool`，由 quic-go/TLS 握手 goroutine 写，`Match()` goroutine 在 `qListener.Accept(qContext)` 返回后读。若 Accept 是因 `qContext.Done()`（deadline 或 WaitForMore 的 `qCancel()`）返回，写/读之间没有显式 happens-before。本机没有 C 编译器，`CGO_ENABLED=0` 导致 `-race` 无法运行；建议 CI 用 `CGO_ENABLED=1 go test -race ./modules/l4quic` 验证，或改成 `atomic.Bool`。
- **全局可变超时**：`QUICAcceptTimeout` 从 `const` 变成 `var`，测试会临时改写它；生产上 100ms→1s 意味着每个走到 quic matcher 的非 QUIC UDP flow 最多多等 900ms（仍在 3s matching timeout 内），属于性能/延迟权衡，需确认可接受。

---

## 5. `84b1e0b`：PROXY protocol packetconn wrapper

新模块 `caddy.packetconns.proxy_protocol` 本身实现自洽，单测覆盖 header 解析和回包路由。但与问题①②的关系是间接的：

- 只有把 `proxy_protocol` 放在 `layer4` 前面，layer4 才能看到裸 QUIC 包，从而让 `parseQUICInitialDCID` 生效；
- 若顺序相反，问题①的检测完全失效；
- `flows` 只按 `clientAddr.String()` 索引，两个不同代理转发同一虚拟客户端地址时后到者覆盖前者，回包可能走错代理；
- `ReadFrom` 对无 PROXY header 的 datagram 直接丢弃（非 fail-open），与同一 socket 上的明文 UDP 业务不兼容。

---

## 6. 测试与验证记录

```
go test ./layer4/... ./modules/l4quic/... ./modules/l4proxy/... ./modules/l4proxyprotocol/...
  ok  github.com/mholt/caddy-l4/layer4            5.899s
  ok  github.com/mholt/caddy-l4/modules/l4quic    5.346s
  ok  github.com/mholt/caddy-l4/modules/l4proxy   2.206s
  ok  github.com/mholt/caddy-l4/modules/l4proxyprotocol 0.188s
```

`go test -race` 因本机 `CGO_ENABLED=0` 且无 gcc/clang 未能执行。

另用三个临时测试（验证后已从工作区删除，git status 干净）确认了：同 DCID 重传不重置、QUIC v2 Initial 漏检、瞬态读错误可被吞掉。

---

## 7. 建议的后续动作（按优先级）

1. **把 `resilientPacketConn` + splitter 重启逻辑抽到公共函数，同时用于 `Server.servePacket` 和 `PacketConnWrapper.WrapPacketConn`**；否则 Caddy HTTP/3 共端口部署仍会断流需重启。
2. **不要用启发式 sniffing 做路由生命周期管理**。更稳的方向：把 flow 的生命周期与匹配结果绑定——匹配失败/上游关闭时由 handler 显式释放 flow（`pc.release`），并允许同一 5 元组在服务器未回包时重新进入匹配；QUIC 场景可用 DCID 作为流键而不是仅靠源地址。
3. 若保留现有方案，至少：扩展 `parseQUICInitialDCID` 支持 v2（`0xd0`），给 800ms 规则加“上游仍无响应”条件，重置时把新 init 包喂给新 flow 而不是丢弃，并给瞬态错误重试加退避/上限。
4. 给 `alpnMismatch` 改成 `atomic.Bool` 并补 ALPN mismatch 单测；在 CI 开启 `-race`。
5. 补两个集成测试：真实 UDP 上游突然关闭后 downstream 是否释放；注入一次 `ECONNREFUSED`/`ECONNRESET` 后 Caddy HTTP/3 + layer4 wrapper 是否继续服务。

---

## 8. 最终判定

> `fix/l4-quic` 把两个问题的**最常见触发路径**都堵上了一部分，现有测试也全绿；但代码审查 + 针对性实验表明：问题①仍有确定漏检（同 DCID 重传、QUIC v2）和误杀窗口（800ms），问题②在 `caddy.packetconns.layer4` 包装路径上**完全没有修复**，且新增的自动重启机制基本不可达。
>
> **因此不能判定“已经完全解决”。** 在确认生产配置走的是 standalone `layer4` app 且客户端为 QUIC v1、握手能在 800ms 内完成之前，不建议视为已闭环。

---

## 9. 修复实施记录（本轮改动）

针对上面已确认的确定性缺陷做了如下修改，全部改动未提交，在工作区中：

| 文件 | 修改 |
|---|---|
| `layer4/resilient_packetconn.go`（新增） | `resilientPacketConn` 抽为包级组件；瞬态读错误按 1ms→25ms 指数退避重试，不再忙循环；closed/timeout 语义保持不变 |
| `layer4/server.go` | `parseQUICInitialDCID` 支持 QUIC v2（`0xd0` / `0x6b3343cf`）并排除 Handshake/Retry/版本协商；删除无条件 800ms 重置；改为“无上游回包 300ms”和“有上游字节但 5s 内从未见到 1-RTT 短包”的停滞判定；DTLS 分支复用同一超时常量 |
| `layer4/packetconn.go` | `PacketConnWrapper.WrapPacketConn` 也用 `resilientPacketConn` 包裹底层 socket，堵住 Caddy HTTP/3 共端口路径的读错误致死问题 |
| `modules/l4quic/matcher.go` | `alpnMismatch` 改为 `atomic.Bool`；ALPN 判定抽成 `hasMatchingALPN` |
| 测试 | 新增 v1/v2/Handshake 解析、晚到重传不误杀、停滞握手仍重置、Caddy wrapper 路径瞬态错误容错、ALPN 判定等用例 |

### 验证结果

```
go test ./...                      全部通过（含 integration 10.3s）
go vet ./layer4/... ./modules/l4quic/... ./modules/l4proxy/... ./modules/l4proxyprotocol/...  通过
gofmt -w 后 git diff --check       通过
```

针对性单测：

- `TestParseQUICInitialDCIDVersions`：v1/v2 Initial 识别正确，v1/v2 Handshake 与版本协商不再误判。
- `TestServePacketLiveHandshakeSurvivesLateRetransmit`：上游持续回包时，900ms 后同 DCID 重传不再误杀 flow（旧代码必杀）。
- `TestServePacketStalledHandshakeResetsFlow`：缩短停滞超时后，上游回垃圾字节但 5s 无 1-RTT 的 flow 会被重置，重传能建立新 handler。
- `TestPacketConnWrapperSurvivesTransientReadError`：Caddy wrapper 路径注入一次瞬态读错误后，fallback 仍能收到并发给客户端数据。
- `TestHasMatchingALPN`：ALPN 命中/不命中/空列表行为明确。

### 仍未消除的限制（非本轮可小改动解决）

1. 触发重置时那个新 Initial 包仍被丢弃，恢复依赖客户端重传；这是 hybrid splitter 只按源地址分流的架构限制。
2. `Server.servePacket` 里的 splitter 自动重启循环依旧基本不可达（hybrid 的失败错误包着 `net.ErrClosed`）；现在主要靠入口处的错误过滤避免走到失败路径。
3. 启发式 sniffing 仍无法 100% 区分“重传的同一会话”与“同端口新会话”；要彻底解决需要把 flow 键扩展到 QUIC DCID 或让 handler 显式释放流重新匹配。
4. 本机无 C 编译器，`-race` 仍未运行；`atomic.Bool` 从代码层面消除了该竞态，CI 仍建议开启竞态检测。

---

## 10. 按“兜底可达、listener 不永久死”原则的收敛调整

在第 9 节基础上，根据明确的部署原则做了最后一次收敛，重点不再是精确识别会话，而是行为保证：

**正常能分流 / 兜底能到达：**

- 检测到同一客户端端口上的新 QUIC Initial 时，不再简单地关闭 flow 并丢包。
  - 有 fallback 的 `caddy.packetconns.layer4` 包装路径：调用 `hybrid.SplitConn.Release`，把**当前包、已排队包以及该 flow 的后续包**整体移交给 fallback，新握手立即到达兜底 proxy，无需等待客户端重传，也不必等 idle timeout。
  - 无 fallback 的 standalone 路径：结束 flow，让下一个包立即重新进入匹配，避免 30s idle timeout 才恢复。
- 通过 `packetConn.released` 防止 handler 侧与喂包 goroutine 重复释放。
- 删掉了第 9 节引入的 5s “停滞握手”启发式；保留简单可靠的三个条件（DCID 变化、见到客户端 1-RTT 短包、上游 300ms 无回包）。过度推断交给兜底 proxy 处理。
- 新增测试 `TestPacketConnWrapperStaleFlowReachesFallback`：第一条流被路由匹配后，同端口不同 DCID 的新 Initial 必须原样出现在 fallback 上。

**UDP listener 彻底不因错误永久停止：**

- `resilientPacketConn` 已同时覆盖 standalone 与 Caddy wrapper 两条路径。
- standalone 的 splitter 重启循环改为用 `socketClosed(pc)`（探测原始 socket 的 `SetReadDeadline`）判断真实关闭；hybrid 把任何失败都包装成 `net.ErrClosed`，因此错误本身不能作为退出依据。现在只有 socket 真关闭才退出，其余失败一律重建 splitter。
- splitter 的 fake `Close` 不再空操作：它给 `rpc` 设置过期 deadline 打断阻塞的读，确保旧 splitter 完全退出后才启动新的，避免两个 reader 竞争、新 flow 被旧 reader 吃掉。Caddy wrapper 路径也用同样的中断函数，避免失败时留下读 goroutine。
- 新增测试 `TestServePacketRestartsAfterSplitterFailure`：注入一次“看起来像连接关闭”的写错误后，socket 仍打开，listener 必须自动重建并在 2s 内继续正常回包。

最终 `go test ./...`、`go vet`、`gofmt`/`git diff --check` 全部通过。

---

## 11. 最后确认：解析成本与 Initial 优先级

### 解析成本

`parseQUICInitialDCID` 只做长度检查、首字节掩码、4 字节版本读取、类型位判断和 DCID 长度检查，随后直接返回输入切片的一个子切片，不复制、不分配。微基准（Windows / Ryzen 5 5600G，3 次）：

```
BenchmarkParseInitial-12        1.88 ns/op    0 B/op    0 allocs/op
BenchmarkParseInitialShort-12   1.40 ns/op    0 B/op    0 allocs/op
```

检测在喂包 goroutine 中进行，且在任何包进入 `readCh` 之前完成。对绝大多数 QUIC 1-RTT 包只是一次 `& 0x80` 判断；对非 QUIC 的短 UDP 包，长度检查即返回。没有额外缓冲、复制或锁。临时基准文件已删除。

### 最高优先级与缓冲覆盖

新 Initial 的检测发生在 `packetConn` 的喂包 goroutine 里，早于 `readCh` 和 `Connection` 的预取缓冲，因此它不会先被路由 matcher 看到。触发 stale 后：

- 新 Initial 作为 `pkts` 的第一个参数传给 `hybrid.SplitConn.Release`，所以它是 fallback 收到的第一个包；
- `readCh` 中已排队但未读的旧 flow 包随后交给 fallback；
- 旧 handler 的 `cx.buf` 预取内容属于旧 flow，随 flow 结束而被丢弃，不会参与新握手；
- `pc.released` 保证 handler 侧不会再调用 `release` 覆盖这个顺序。

新增的 `TestPacketConnWrapperStaleFlowReachesFallback` 先在旧 flow 上排入一个旧包，再发新 Initial，连续 5 次验证 fallback 总是先收到新 Initial，然后才收到旧包。



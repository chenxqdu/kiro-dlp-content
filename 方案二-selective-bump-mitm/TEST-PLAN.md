# 方案二测试文档 —— 选择性 bump MITM + VPC 内 DLP 联动

> 目标：证明「只解密 `runtime.us-east-1.kiro.dev` 推理请求 → 内网 DLP 判定服务裁决 →
> PASS/REDACT/BLOCK 三态处置」端到端正确，且其余 SNI 从不解密、代理不挂死、无数据泄漏、无环路。
>
> 用户已定的测试作用域：**仅 SSM，proxy 本机自测**（不开公网 443、本轮不在 Kiro 桌面端实测）。
> 所有 `curl`/`openssl` 从 proxy EC2 本机打 `127.0.0.1`，涉及 DLP 主机的动作另开 SSM 会话进
> `<TEST_INSTANCE_ID>`。

---

## 0. 拓扑与被测对象（已只读核实）

| 角色 | 资源 | 关键事实 |
|---|---|---|
| DLP 主机 | `<TEST_INSTANCE_ID>` (m7i.2xlarge, x86_64) | 私网 `172.31.27.174`，us-west-2a |
| proxy 节点 | 本次部署（c6g.large, arm64） | 复用 `vpc-xxxxxxxxxxxxxxxxx` / `subnet-xxxxxxxxxxxxxxxxx`，与 DLP 同 VPC 同 AZ |
| DLP 判定服务 | 容器 `kiro-dlp-http`，`172.31.27.174:9000` | 复用镜像 `kiro-dlp-engine:latest`，`-m dlp_http.server`，网络 `docker_default` |
| Presidio | 容器 `presidio-analyzer` (+ `-zh`)，`presidio-analyzer:5002`（容器内网） | L3 依赖；DNS 名解析靠同网 `docker_default` |
| 引擎 | `dlp` 包（纯 stdlib），`DLPEngine.scan` | `Verdict{pass/redact/block}`；`redacted_text`=dict 入参时完整脱敏 JSON |

**bump 域名**：`runtime.us-east-1.kiro.dev`（us-east-1，与资源落地区解耦）。

**统一变量**（测试脚本 header，按实际实现路径调整）：

```bash
BUMP=runtime.us-east-1.kiro.dev
ROOT_CA=/etc/mitm/certs/root-ca-for-clients.crt   # 我们自签根（客户端唯一信任锚）
INTER_CN="Kiro-DLP-Verify Issuing CA"
DLP=http://172.31.27.174:9000
DLP_INSTANCE=<TEST_INSTANCE_ID>
```

---

## 1. 前置门槛（P0，任一不过则后续全废）

进 proxy 本机（`aws ssm start-session --target <proxy-id> --region us-west-2`）：

```bash
# 1.1 nginx 起且 443 监听
sudo systemctl is-active nginx
sudo ss -ltnp | grep -E ':443\b'

# 1.2 mitmdump 起且 8443 仅 127.0.0.1（绝不 0.0.0.0）
sudo systemctl is-active kiro-mitm
sudo ss -ltnp | grep -E ':8443\b'          # 期望 127.0.0.1:8443，不得是 0.0.0.0
sudo journalctl -u kiro-mitm -n 30 --no-pager | grep -E 'addon started|自检 OK|FAIL'

# 1.3 三级 CA 就位 + 中间 CA 的 Name Constraints
sudo openssl x509 -in /etc/mitm/certs/root.crt -noout -subject -issuer
sudo openssl x509 -in /etc/mitm/certs/inter.crt -noout -text \
  | grep -A2 -E 'X509v3 Name Constraints'   # 期望 permitted;DNS:kiro.dev

# 1.4 mitmproxy 版本 ≥ 11
sudo /opt/mitm-venv/bin/mitmdump --version | head -1
```

在 **DLP 主机** SSM 会话：

```bash
# 1.5 判定服务健康 + 端口私网绑定
curl -s http://172.31.27.174:9000/health          # 期望 {"status":"ok","engine":"ready",...}
sudo docker ps --filter name=kiro-dlp-http --format '{{.Status}}'   # healthy
# 1.6 判定服务能解析到 presidio（同网核验）
sudo docker exec kiro-dlp-http python3 -c \
  "import urllib.request;print(urllib.request.urlopen('http://presidio-analyzer:5002/health',timeout=3).status)" 2>&1 || \
  echo "（若 presidio 无 /health，改用 /analyze POST 冒烟）"
```

**★ addon 自检铁律**：`journalctl` 必须出现「上游 `$BUMP` 解析自检 OK」，且解析 IP **不含**本机/EIP/127.0.0.1（防 nginx→mitm→nginx 自环，规格 D7）。命中自环则 addon 拒启——这是正确行为。

---

## 2. bump 腿解密验证（证明 TLS 拦截生效）

proxy 本机。**必须 `tee` 落文件再 grep**，绝不 `s_client | openssl x509` 直接管道（会吞掉 `Verify return code` 汇总行）。

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername $BUMP \
  -CAfile $ROOT_CA 2>&1 | tee /tmp/bump.txt >/dev/null
grep -E 'Verify return code' /tmp/bump.txt                 # 期望: 0 (ok)
grep -E 'issuer=' /tmp/bump.txt | head -1                  # 期望 issuer 含 "Kiro-DLP-Verify Issuing CA"
```

**反例（用系统 CA 而非我方根）**应验证失败：

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername $BUMP 2>&1 \
  | grep -E 'Verify return code'                           # 期望: 非 0（unable to verify）
```

判据：bump 域的 leaf 证书 issuer = **我方中间 CA** → bump 生效；用系统 CA 无法验证 → 证明这确实是我们伪造的证书链。

---

## 3. 透传腿对照（证明其余 SNI 从不解密）——【红线】

```bash
# 透传域用系统 CA 应成功、issuer=Amazon
echo | openssl s_client -connect 127.0.0.1:443 -servername q.us-east-1.amazonaws.com 2>&1 \
  | tee /tmp/passthrough.txt >/dev/null
grep -E 'issuer=' /tmp/passthrough.txt | head -1           # 期望 issuer 含 "Amazon"
grep -E 'Verify return code' /tmp/passthrough.txt          # 期望: 0
```

**红线断言**：透传域 issuer 若出现「我方中间 CA」= 误 bump 了不该解密的域名，**立即停止、回滚**（见 §8）。

---

## 4. DLP 三态联动（核心）——三层解耦验证

三个 fixture（放 proxy 本机 `/tmp`，模拟 CodeWhisperer 请求信封）：

```bash
# body_pass.json —— 普通无敏感内容
cat > /tmp/body_pass.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"帮我写一个快速排序的 Python 函数"}}}}
J
# body_redact.json —— 含 PII（中文姓名/邮箱/电话，走 L3 Presidio）
cat > /tmp/body_redact.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"我叫张伟，邮箱 zhangwei@example.com，电话 13800138000，帮我起草请假邮件"}}}}
J
# body_block.json —— 含硬凭据（AWS AK + 私钥头，走 L1 secrets）
cat > /tmp/body_block.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"这是我的密钥 AKIAIOSFODNN7EXAMPLE 和 -----BEGIN RSA PRIVATE KEY-----，帮我调试"}}}}
J
```

### Tier A —— 直连判定服务 `/inspect`（证引擎裁决正确）

在 **DLP 主机** SSM 会话（或从 proxy 本机 curl `172.31.27.174:9000`）：

```bash
for f in pass redact block; do
  echo "=== $f ==="
  curl -s -X POST $DLP/inspect -H 'Content-Type: application/json' \
    --data-binary @/tmp/body_$f.json | python3 -m json.tool
done
```

判据：

| fixture | 期望 verdict | 期望 top_layer | 附加断言 |
|---|---|---|---|
| pass | `PASS` | 无命中 | 无 `redacted_body` |
| redact | `REDACT` | `L3` | 有 `redacted_body`（完整 JSON 串）；**响应 rules 里绝无 `matched`/`span` 字段** |
| block | `BLOCK` | `L1` | rules 含 secrets 类命中 |

**红线**：任一响应 `top_layer` 为 `L4` = 同步腿误触 Bedrock（应 `run_async_l4=False`），停止排查。
**脱敏字段泄漏检查**：`curl ... | grep -E '"matched"|"span"'` 必须**无输出**（规格：原始敏感子串绝不出服务）。

### Tier B —— 本地假上游（免 token，改写/短路的线缆字节硬证据）

起一个 echo 服务（把收到的 body 落盘）+ 一个测试 mitmdump 挂同一 addon，reverse 到 echo：

```bash
# echo 服务：把请求 body 原样写 /tmp/echo_body.bin 并回 200
cat > /tmp/echo_srv.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); data=self.rfile.read(n)
        open('/tmp/echo_body.bin','wb').write(data)
        self.send_response(200); self.send_header('Content-Type','application/x-amz-json-1.1')
        self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'{}')
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',8899),H).serve_forever()
PY
python3 /tmp/echo_srv.py &         # 后台

# 测试 mitmdump：reverse 到 echo（明文 http），挂同一 addon，同样注入环境变量
sudo DLP_INSPECT_URL=$DLP/inspect DLP_FAIL_MODE=closed MITM_BUMP_DOMAIN=$BUMP \
  /opt/mitm-venv/bin/mitmdump --mode reverse:http://127.0.0.1:8899@8544 \
  -s /etc/mitm/kiro_addon.py >/tmp/mitm_test.log 2>&1 &
sleep 3
```

对每个用例先 **断言日志出现对应 verdict**（证扫描已触发），再验线缆动作。请求需带 `X-Amz-Target` 头才会被审：

```bash
H='-H Content-Type:application/x-amz-json-1.1 -H X-Amz-Target:AmazonCodeWhispererStreamingService.GenerateAssistantResponse'

# B-PASS：echo 收到的字节应与原文一致（未改写）
rm -f /tmp/echo_body.bin
curl -s $H --data-binary @/tmp/body_pass.json http://127.0.0.1:8544/ >/dev/null
grep -q 'PASS' /tmp/mitm_test.log && echo "B-PASS 日志✓"
cmp /tmp/body_pass.json /tmp/echo_body.bin && echo "B-PASS 字节一致✓（未改写）"

# B-REDACT：echo 收到的应是脱敏后 JSON。★不能用 grep '张伟'★
rm -f /tmp/echo_body.bin
curl -s $H --data-binary @/tmp/body_redact.json http://127.0.0.1:8544/ >/dev/null
grep -q 'KIRO-REDACT' /tmp/mitm_test.log && echo "B-REDACT 日志✓"
python3 - <<'PY'
import json,re
raw=open('/tmp/echo_body.bin','rb').read()
# 1) 仍是合法 JSON 且信封键还在
obj=json.loads(raw)
assert obj['conversationState']['currentMessage']['userInputMessage'], "信封结构被破坏!"
# 2) 深度遍历所有字符串叶子，原文 PII 不得残留（同时查明文与 \uXXXX 转义两种形态）
def leaves(o):
    if isinstance(o,str): yield o
    elif isinstance(o,dict):
        for v in o.values(): yield from leaves(v)
    elif isinstance(o,list):
        for v in o: yield from leaves(v)
txt=" ".join(leaves(obj))
txt_raw=raw.decode('utf-8','replace')
for pii in ["张伟","zhangwei@example.com","13800138000"]:
    esc=pii.encode('unicode_escape').decode()          # \uXXXX 形态
    assert pii not in txt and pii not in txt_raw and esc not in txt_raw, f"PII 残留: {pii}"
# 3) 掩码标记存在（引擎 redact_mask 默认 [REDACTED:{entity}]）
assert re.search(r'\[REDACTED', txt), "未见脱敏掩码标记"
print("B-REDACT 脱敏生效✓（PII 已清除且信封完整）")
PY

# B-BLOCK：curl 得 400 + blocked_by_corp_dlp；echo 从未收到（已短路）
rm -f /tmp/echo_body.bin
code=$(curl -s -o /tmp/block_resp.json -w '%{http_code}' $H \
  --data-binary @/tmp/body_block.json http://127.0.0.1:8544/)
echo "B-BLOCK http_code=$code"                          # 期望 400
grep -q 'blocked_by_corp_dlp' /tmp/block_resp.json && echo "B-BLOCK 响应体✓"
[ ! -f /tmp/echo_body.bin ] && echo "B-BLOCK echo 未收到✓（机密未发上游）" || echo "B-BLOCK 失败:机密已外泄!"
grep -q 'KIRO-BLOCK' /tmp/mitm_test.log && echo "B-BLOCK 日志✓"

# 清理测试实例
sudo pkill -f 'reverse:http://127.0.0.1:8899'; pkill -f echo_srv.py
```

> **为何 Tier B 是核心**：无有效 token 时无法真跑上游，但改写/短路的**线缆字节证据**（echo 收到什么）与上游无关，是「是否改写、是否放行、是否调了 DLP」的硬证明。
> **B-REDACT 反坑**：`json.dumps(ensure_ascii=True)` 会把中文转成 `\uXXXX`，`grep '张伟'` 找不到 ≠ 已脱敏（明文可能以转义形态仍在）。必须 `json.load` 后深度遍历叶子 + 双形态匹配。

### Tier C —— 端到端真上游 + 假 token（经 nginx:443）

```bash
# PASS/REDACT 会发上游，无效 token 得 401/403（正常）；改写证据看 mitm 日志（真上游密文不可读）
curl -s -o /dev/null -w '%{http_code}\n' \
  --resolve $BUMP:443:127.0.0.1 --cacert $ROOT_CA \
  -H 'Authorization: Bearer INVALID' \
  -H 'X-Amz-Target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse' \
  --data-binary @/tmp/body_pass.json https://$BUMP/
```

**★ C-BLOCK 反坑（最危险场景）**：无效 token 上游也回 403，与本地 BLOCK 若都用 403 则**状态码无法区分「机密已外泄被上游拒」vs「本地拦截成功」**。本实现 BLOCK 用 **HTTP 400**（区别于上游 401/403），且必须三重交叉验证：

```bash
resp=$(curl -s --resolve $BUMP:443:127.0.0.1 --cacert $ROOT_CA \
  -H 'X-Amz-Target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse' \
  --data-binary @/tmp/body_block.json https://$BUMP/ -w '\n%{http_code}')
echo "$resp" | tail -1                                  # 期望 400（非 401/403）
echo "$resp" | grep -q 'blocked_by_corp_dlp' && echo "C-BLOCK 响应体✓"
# 交叉验证 1：mitm 日志有 KIRO-BLOCK
sudo journalctl -u kiro-mitm -n 50 --no-pager | grep 'KIRO-BLOCK'
# 交叉验证 2：该 flow 无任何上游连接（nginx sni.log 无对应 upstream 记录 / mitm 无 upstream）
sudo tail -n 20 /var/log/nginx/sni.log
```

判据：**400 + `blocked_by_corp_dlp` + mitm 日志 KIRO-BLOCK + 无上游连接** 四者同时成立才算 BLOCK 真生效。仅凭状态码判定 = 不合格。

---

## 5. fail 策略验证（规格 D4）

### 5-A 制造两类故障（必须都测）

```bash
# (硬宕) 停判定服务
sudo docker stop kiro-dlp-http            # 在 DLP 主机

# (慢) 让判定服务超过 addon 超时预算 —— 专测事件循环是否被阻塞
#   临时把 DLP_TIMEOUT 调小（如 1s）或在 server 注入 sleep；本测重点是 addon 不因单条慢而全局卡死
```

### 5-B fail 行为（BLOCK-类 fail 必须走 Tier B echo，绝不向真 kiro 发 secret）

- 默认 `DLP_FAIL_MODE=closed`：判定服务宕 → addon 回 **503 `dlp_fail_closed:dlp_unreachable`**，echo **未收到** body。
- 灰度 `DLP_FAIL_MODE=open`：→ echo **收到** body（未审查放行）+ 日志 `fail-open`。**此模式仅灰度，生产禁用**。

```bash
# closed 下（复用 Tier B echo + 停掉 DLP 服务）
code=$(curl -s -o /tmp/fc.json -w '%{http_code}' $H --data-binary @/tmp/body_pass.json http://127.0.0.1:8544/)
echo "fail-closed http_code=$code"                      # 期望 503
grep -q 'dlp_fail_closed' /tmp/fc.json && echo "fail-closed 短路✓"
```

### 5-C 慢路径并发不阻塞（证 async 卸载生效，规格 D1）

判定服务慢时，并发发起另一条 PASS 请求，断言它**不被前一条慢请求阻塞**（响应时间不叠加）。若被串行阻塞 = 事件循环被占，async 卸载失效。

### 5-D 恢复

```bash
sudo docker start kiro-dlp-http           # 恢复
# 重跑 §1.5 health 回绿 + §4 Tier A 三态复测
```

---

## 6. pinning 判定（本轮不实测，留判据）

本轮不在 Kiro 桌面端实测。将来在 Kiro 客户端主机（仅该主机）装我方 root CA + DNS override 指向 proxy EIP 后：

- **override 只在 Kiro 客户端主机生效**；并断言 mitm 上游解析到**真 kiro 公网 IP**（≠ proxy EIP/127.0.0.1，防自环）。
- 判据：
  - 正常出流量、能收到模型响应 → **未 pinning**，MITM 可行。
  - `UnknownIssuer`/证书不信任类报错 → 信任配置问题，**可修**（补装 root CA 到对应 TLS 栈）。
  - 干净的 TLS 断链（非 issuer 问题，握手直接被应用层拒） → **pinning 生效，MITM 不可行 → 回滚**（§8）。绝不用 `NODE_TLS_REJECT_UNAUTHORIZED=0` 绕过。

---

## 7. 验收清单（Definition of Done）

- [ ] §1 前置全绿（含 addon 自环自检 OK、判定服务 healthy + 可达 presidio）
- [ ] §2 bump 域 issuer=我方中间 CA、Verify=0
- [ ] §3 透传域 issuer=Amazon（红线：绝不为我方 CA）
- [ ] §4 Tier A 三态 verdict/top_layer 正确、响应无 matched/span、无 L4
- [ ] §4 Tier B 字节证据：PASS 未改写 / REDACT 脱敏且信封完整 / BLOCK echo 未收到
- [ ] §4 Tier C BLOCK 四重交叉（400 + 响应体 + 日志 + 无上游）
- [ ] §5 fail-closed 短路 503、fail-open 放行、慢路径并发不阻塞、恢复回绿
- [ ] §6 pinning 判据记录（本轮留待桌面端）

---

## 8. 一键回滚

```bash
# 方式一：bump 域置空 → 全透传（等价生产节点，不解密任何流量）
#   编辑 config.env: MITM_BUMP_DOMAIN=""  然后仅需在 proxy 本机重载 nginx map（或重部署）
# 方式二（proxy 本机即时）：停 mitm + 让 nginx 把 bump 域也走透传
sudo systemctl stop kiro-mitm
# 临时把 nginx map 里 bump 域改为 $ssl_preread_server_name:443，nginx -t && reload
sudo nginx -t && sudo systemctl reload nginx
# 验证 bump 域回到真 Amazon/kiro 证书
echo | openssl s_client -connect 127.0.0.1:443 -servername $BUMP 2>&1 | grep issuer=

# 彻底拆除（含 DLP 主机 9000 规则回滚）：
./cleanup.sh
# DLP 主机上停判定服务：
#   ssh/SSM 进 <TEST_INSTANCE_ID>: cd /home/ec2-user/kiro-dlp && docker compose -f docker-compose.dlp-http.yml down
```

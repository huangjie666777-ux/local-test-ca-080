# Local Test CA

本机联调用的迷你证书签发/吊销后端（FastAPI + `cryptography`）。只监听 `127.0.0.1`，无前端。

## 启动

```sh
.venv/bin/python -m pip install -r requirements.lock.txt

# 数据目录默认为 ./data，可用 CA_DATA_DIR 覆盖
CA_DATA_DIR=./data .venv/bin/python -m uvicorn app.main:app \
    --host 127.0.0.1 --port 8000

.venv/bin/python -m pytest
```

数据目录为空时自动生成 4096 位自签根 CA；重启直接复用。目录非空但缺少 `ca.key.pem`、
`ca.cert.pem` 或数据库，或数据库记录的 CA 指纹与证书不匹配时，服务拒绝启动。

## 密钥存放

- 根私钥：`$CA_DATA_DIR/ca.key.pem`（PKCS#8 PEM，创建时权限 `0600`，仅本机磁盘存储，不通过网络暴露）。
- 根证书：`$CA_DATA_DIR/ca.cert.pem`，可公开下载。
- SQLite：`$CA_DATA_DIR/ca.sqlite3`（WAL 模式，记录证书、幂等键、吊销状态、CRL 编号）。
- 已发布 CRL：`$CA_DATA_DIR/crl.pem`（原子替换写入）。
`data/` 已在 `.gitignore` 中忽略。

## 签发策略

- CSR 必须是合法 PEM 且签名可验证；公钥仅接受 ≥2048 位 RSA。
- `subjectAltName` 必填、非空，且只允许 DNS 名称；CN 不能代替 SAN。
- 名称按标签精确匹配 `lab.test` 及其子域（大小写不敏感，规范化为小写），拒绝通配符、
  非法标签和尾随点等形式；不复制 CSR 中的其他扩展。
- `days` 为 1–30 的整数；证书 `BasicConstraints CA=false`、KeyUsage
  `digitalSignature,keyEncipherment`、EKU 仅 `serverAuth`，notAfter 不超过 CA 到期时间。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/health` | 健康检查 |
| GET  | `/ca` | 下载根 CA 证书（PEM） |
| POST | `/certificates` | 提交 `{"csr", "days", "idempotency_key"}` 签发；成功返回序列号与 PEM |
| GET  | `/certificates/{serial}` | 查询证书 PEM、SAN 与吊销状态 |
| POST | `/certificates/{serial}/revoke` | 提交 `{"reason"}` 吊销；同原因幂等、异原因 409、未知序列号 404 |
| POST | `/crl/publish` | 发布新的完整 CRL，返回递增且持久化的 `crl_number` |
| GET  | `/crl` | 下载当前已发布的 CRL（PEM，CA 签名） |

幂等语义：同 `idempotency_key` + 同 CSR(DER) + 同 `days` 返回原证书（HTTP 200）；
同键不同内容返回 409。签发在单个 SQLite 立即事务内完成（先分配序列号再签名回填），
并发重试只产生一条记录，签名失败不留半成品，重启后仍然成立。

支持的吊销原因：`unspecified`、`key_compromise`、`ca_compromise`、`affiliation_changed`、
`superseded`、`cessation_of_operation`、`certificate_hold`、`privilege_withdrawn`、`aa_compromise`。
吊销不可撤回，首次吊销时间永久保留。

## curl 示例

```sh
# 1) 生成私钥与 CSR（CN 可留空，SAN 由配置写入）
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj / -addext 'subjectAltName=DNS:api.lab.test,DNS:www.lab.test'

# 2) 下载根 CA
curl -s http://127.0.0.1:8000/ca -o ca.cert.pem

# 3) 签发（CSR 较大，建议用 jq 组 JSON）
jq -n --rawfile csr server.csr '{csr:$csr, days:15, idempotency_key:"req-1"}' \
  | curl -s -X POST http://127.0.0.1:8000/certificates \
      -H 'Content-Type: application/json' --data @- > issue.json
jq -r .certificate issue.json > server.cert.pem

# 4) 查询 / 吊销 / 发布 CRL
curl -s http://127.0.0.1:8000/certificates/$(jq -r .serial_number issue.json)
curl -s -X POST http://127.0.0.1:8000/certificates/1/revoke \
    -H 'Content-Type: application/json' -d '{"reason":"key_compromise"}'
curl -s -X POST http://127.0.0.1:8000/crl/publish
curl -s http://127.0.0.1:8000/crl -o crl.pem

openssl verify -CAfile ca.cert.pem server.cert.pem
```

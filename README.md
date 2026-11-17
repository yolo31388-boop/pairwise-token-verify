# pairwise-token-verify

登录网关一换密钥就全站掉线：JWT 校验只比较 alg 字符串，RS256 和 HS256 混用没有绑定密钥类型；kid 直接拼进 JWKS 路径，未命中时回退到内置公钥；aud 和 iss 只做非空检查，跨租户 token 能过；exp 用本地时间比较，容器时钟漂移 5 分钟就误判；密钥轮换后旧 token 没有宽限期，用户被强制重登；黑名单只存内存，多副本节点各自失效不同步。auth/token_verify.py 是核心，tests/test_token_verify.py 15个红。要修的是：alg 与密钥类型绑定；kid 白名单；aud/iss 精确匹配；UTC 时钟偏差；轮换宽限；共享吊销表。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。

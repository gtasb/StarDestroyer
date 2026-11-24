# 已知盲区与待补边清单

本文件记录静态分析必然断链的位置。**发现即登记，禁止绕过，禁止自行补边后当作已验证事实。**

## 盲区类别

| 类别 | 表现 | 影响 |
|---|---|---|
| 反射 | `Class.forName` / `Method.invoke` / `getBean(name)` | 调用目标在运行时才确定 |
| 动态代理 | CGLIB / JDK Proxy / AOP 织入 | 源码里看不到被调用的实现 |
| SPI | `ServiceLoader` / XML 装配 | 接口与实现的关系不在源码中 |
| 二阶污点 | `JobDataMap` → DB → 另一节点读出 | 污点跨存储/跨消息中断 |
| 表达式引擎 | SpEL / OGNL / Groovy / `ScriptEngine.eval` | 字符串即代码，静态无法判定落点 |
| 继承 | Opengrep 对部分继承关系未实现跟踪 | 子类实现的方法可能漏掉 |
| 库内部 | 无源码的第三方库 | 链在库边界断开 |

## 待补边登记表

格式固定，新增一行即一条：

```
断点位置 | 缺失边（from → to） | 建议 Cypher | 依据
```

示例（未验证时 `依据` 写「推测，待人工确认」，并保持 `manual: true`）：

```
OrderService.run(OrderService.java:88) | OrderService.run → Job.execute(jobName 由 DB 决定) | MATCH (q:Quest) ... | 推测，待人工确认
```

## 补边的纪律

1. 补出来的边必须标 `manual: true`。
2. 报告中手工边与引擎边分列，不得混排。
3. 未人工确认的手工边，结论状态最高只能是 `needs_review`。

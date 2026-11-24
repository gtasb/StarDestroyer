# SQL 注入审计要点

## 判定顺序

1. 先确认入口是否外部可达：路由、鉴权、参数绑定方式。
2. 再看污点是否被隐式净化：类型转换、白名单、ORM 参数绑定都会断链。
3. 最后确认 sink 真的执行：死代码、被 try 吞掉、未调用的分支都不算。

## 典型 sink

- Java：`Statement.execute*`、`JdbcTemplate.query*`、`EntityManager.createNativeQuery`
- Python：`cursor.execute`、`db.session.execute`
- Go：`db.Query/Exec`、`gorm.DB.Raw`

## 常见误报

- 框架层已转义（Thymeleaf、Spring 类型转换）
- 参数来自配置或环境变量，而非请求
- 测试代码与示例代码

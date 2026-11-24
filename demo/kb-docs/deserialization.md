# 反序列化利用链审计

## 入口

Java 原生反序列化的入口方法固定：`readObject`、`readResolve`、`readExternal`。
Hessian、XStream 等机制的入口不同，但最终都会汇聚到危险方法调用。

## 判定要点

- 入口类必须实现 `Serializable`，且入口方法可被外部数据触发。
- 链路上每一跳都要求参数可控：常量、配置值会断链。
- 终点 sink 常见为 `Runtime.exec`、`Class.forName`、`Method.invoke`。

## 与污点分析的区别

这类链通常没有「外部输入」这个 source，源码级污点扫描往往 0 命中，
需要靠调用图从入口反推。这正是静态污点引擎的盲区。

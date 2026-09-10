// ScholarVPN Android —— 根构建配置
// 纯 Kotlin 实现（零 native 依赖）：协议栈重写见 app/src/main/java/com/scholarvpn/client/tunnel
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.20" apply false
}

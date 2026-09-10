plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.scholarvpn.client"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.scholarvpn.client"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // 用 debug 签名使 release 包可直接安装（自用分发）；
            // 正式对外分发请创建独立 keystore 并替换 signingConfig
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")

    // 私钥加密存储（Android Keystore 硬件后备密钥加密，等价 Windows 端 DPAPI 角色）
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // 密码学原语：Ed25519 / X25519 用 BouncyCastle 轻量 API（raw 级别，
    // 无需 Provider 注册）；AES-GCM / HMAC-SHA256 用平台 javax.crypto（Conscrypt 硬件加速）
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

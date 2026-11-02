package com.scholarvpn.client.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * 用户协议门禁（2026-11-02 防滥用）：首次启动全屏展示协议，
 * 勾选并点「同意并继续」后才放行 content；拒绝则 finish()。
 * 同意结果存 SharedPreferences（scholarvpn_general / agreement_accepted）。
 */
@Composable
fun AgreementGate(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val prefs = remember {
        context.getSharedPreferences("scholarvpn_general", android.content.Context.MODE_PRIVATE)
    }
    var accepted by remember { mutableStateOf(prefs.getBoolean("agreement_accepted", false)) }

    if (accepted) {
        content()
        return
    }

    var checked by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp)
    ) {
        Text(
            "ScholarVPN 用户协议",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "最后更新：2026-11-02",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))

        Text(
            AgreementText.TEXT,
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
            style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = checked, onCheckedChange = { checked = it })
            Text("我已阅读并同意以上用户协议")
        }
        Spacer(Modifier.height(8.dp))
        Row {
            TextButton(
                onClick = {
                    prefs.edit().putBoolean("agreement_rejected", true).apply()
                    (context as? android.app.Activity)?.finish()
                },
                modifier = Modifier.weight(1f),
            ) { Text("拒绝并退出") }
            Spacer(Modifier.width(12.dp))
            Button(
                onClick = {
                    prefs.edit().putBoolean("agreement_accepted", true).apply()
                    accepted = true
                },
                enabled = checked,
                modifier = Modifier.weight(1f),
            ) { Text("同意并继续") }
        }
        Spacer(Modifier.height(12.dp))
    }
}

object AgreementText {
    const val TEXT = """ScholarVPN 用户协议

最后更新：2026-11-02

一、软件用途
本软件仅供学习、研究和技术交流使用。使用本软件访问网络时，您应遵守所在
国家/地区的法律法规；因违反法律法规产生的一切责任由您本人承担。

二、禁止行为
您承诺不利用本软件从事任何违法违规活动，包括但不限于：
  · 传播违法违规信息，或侵犯他人合法权益；
  · 对任何计算机系统进行未授权访问、攻击或干扰；
  · 滥用、破坏本服务或其他用户的正常使用体验。

三、受管服务与数据说明（仅「使用服务方服务器」模式适用）
1. 为提供试用与授权管理，本软件会向服务方提交：随机设备指纹（由系统级
   设备标识经单向哈希生成，不含姓名、手机号等任何个人身份信息）、操作
   系统与硬件概述、设备品牌与型号。
2. 服务端会记录您的接入时间与流量统计，并对经隧道出站的域名访问做合规
   审计。
3. 如不接受上述数据采集，请选择「自建服务器」模式——该模式不产生任何
   上述上报，功能也不受影响。

四、服务说明
本服务按「现状」提供，不承诺可用性与性能。服务方对滥用、违规行为有权
限制、暂停或终止服务，并保留追究相关责任的权利。

五、免责与责任限制
在法律允许的最大范围内，服务方不对因使用本软件所造成的任何直接或间接
损失承担责任。

继续安装或使用本软件，即表示您已阅读、理解并同意本协议的全部内容。"""
}

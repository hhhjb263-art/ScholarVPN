package com.scholarvpn.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.scholarvpn.client.ui.ScholarVpnTheme
import com.scholarvpn.client.vpn.ServerEntry
import com.scholarvpn.client.vpn.VpnSettings
import com.scholarvpn.client.vpn.VpnStatus

/**
 * 主界面：品牌栏 + 渐变状态英雄卡 + 服务器卡片列表（点卡片连接）+ 添加/编辑/删除 + FAB。
 * TODO(M3)：卡片滑动删除、导入导出配置。
 */
class MainActivity : ComponentActivity() {

    private var granted by mutableStateOf(false)
    private val servers = mutableStateListOf<ServerEntry>()
    private var editingIndex by mutableStateOf<Int?>(null)   // null=关闭编辑器；-1=新增
    private var activeIndex by mutableStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        granted = VpnService.prepare(this) == null
        reloadServers()
        setContent {
            ScholarVpnTheme {
                // Service 清令牌（注册成功消费/令牌失效作废）后自动刷新卡片，
                // 防止界面内存里的废令牌被编辑保存回存储（"连接后秒拒"的根因）
                LaunchedEffect(Unit) {
                    VpnStatus.tokenClearTick.collect { reloadServers() }
                }

                Box(modifier = Modifier.fillMaxSize().systemBarsPadding()) {
                    val phase by VpnStatus.phase.collectAsState()
                    val status by VpnStatus.message.collectAsState()
                    val busyIdx by VpnStatus.busyIndex.collectAsState()
                    val busy = VpnStatus.isBusy(phase)

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 20.dp),
                    ) {
                        Spacer(Modifier.height(8.dp))

                        BrandHeader()

                        Spacer(Modifier.height(16.dp))

                        StatusHero(
                            phase = phase,
                            message = status,
                            busyServer = servers.getOrNull(busyIdx),
                        )

                        Spacer(Modifier.height(16.dp))

                        Box(modifier = Modifier.weight(1f)) {
                            if (servers.isEmpty()) {
                                EmptyState(onAdd = { editingIndex = -1 })
                            } else {
                                LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    itemsIndexed(servers) { index, s ->
                                        ServerCard(
                                            entry = s,
                                            selected = index == activeIndex,
                                            // 本卡正在连接/已连接（断开按钮渲染在本卡上）
                                            isBusyCard = busy && busyIdx == index,
                                            connecting = busy && busyIdx == index &&
                                                phase != VpnStatus.Phase.CONNECTED,
                                            otherBusy = busy && busyIdx != index,
                                            onSelect = {
                                                activeIndex = index
                                                saveServers()
                                            },
                                            onEdit = { editingIndex = index },
                                            onConnect = {
                                                activeIndex = index
                                                saveServers()
                                                connectActive()
                                            },
                                            onDisconnect = { disconnect() },
                                        )
                                    }
                                    item { Spacer(Modifier.height(72.dp)) }
                                }
                            }
                        }
                    }

                    // 右下角 +：添加服务器
                    FloatingActionButton(
                        onClick = { editingIndex = -1 },
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(24.dp),
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = "添加服务器")
                    }

                    // 回到空闲/失败态时从存储重载：服务端可能已自动清空令牌
                    // （拒绝时 UI 内存里的旧列表不得把令牌又存回去）
                    LaunchedEffect(phase) {
                        if (phase == VpnStatus.Phase.IDLE || phase == VpnStatus.Phase.FAILED) {
                            reloadServers()
                        }
                    }

                    val editIdx = editingIndex
                    if (editIdx != null) {
                        val onDelete: (() -> Unit)? = if (editIdx >= 0) {
                            {
                                servers.removeAt(editIdx)
                                if (activeIndex >= servers.size) {
                                    activeIndex = (servers.size - 1).coerceAtLeast(0)
                                }
                                saveServers()
                                editingIndex = null
                            }
                        } else null
                        ServerEditor(
                            initial = if (editIdx >= 0) servers.getOrNull(editIdx) else null,
                            onDismiss = { editingIndex = null },
                            onSave = { entry ->
                                if (editIdx >= 0) servers[editIdx] = entry else servers.add(entry)
                                if (editIdx < 0) activeIndex = servers.size - 1
                                saveServers()
                                editingIndex = null
                            },
                            onDelete = onDelete,
                        )
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // 回到前台时以存储为准刷新（Service 可能已清令牌/改配置）
        reloadServers()
    }

    private fun reloadServers() {
        val store = VpnSettings(this)
        servers.clear()
        servers.addAll(store.loadServers())
        activeIndex = store.activeIndex().coerceIn(0, (servers.size - 1).coerceAtLeast(0))
    }

    private fun saveServers() {
        val store = VpnSettings(this)
        store.saveServers(servers.toList())
        store.setActiveIndex(activeIndex)
    }

    private fun connectActive() {
        if (servers.isEmpty()) return
        saveServers()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, REQUEST_VPN)
        } else {
            granted = true
            startVpnService()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == Activity.RESULT_OK) {
            granted = true
            startVpnService()
        }
    }

    private fun startVpnService() {
        startForegroundService(
            Intent(this, com.scholarvpn.client.vpn.ScholarVpnService::class.java).apply {
                action = com.scholarvpn.client.vpn.ScholarVpnService.ACTION_CONNECT
            })
    }

    private fun disconnect() {
        startService(
            Intent(this, com.scholarvpn.client.vpn.ScholarVpnService::class.java).apply {
                action = com.scholarvpn.client.vpn.ScholarVpnService.ACTION_DISCONNECT
            })
    }

    private companion object {
        const val REQUEST_VPN = 1
    }
}

/** 品牌 logo 渐变（状态英雄卡与 logo 底共用） */
@Composable
private fun brandBrush(): Brush {
    return if (isSystemInDarkTheme()) {
        Brush.linearGradient(listOf(Color(0xFF3B47B0), Color(0xFF6B3FB8)))
    } else {
        Brush.linearGradient(listOf(Color(0xFF4C5BD4), Color(0xFF925BD4)))
    }
}

/** 顶部品牌栏：渐变 logo 块 + 应用名 */
@Composable
private fun BrandHeader() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(MaterialTheme.shapes.small)
                .background(brandBrush()),
            contentAlignment = Alignment.Center,
        ) {
            Text("S", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 20.sp)
        }
        Spacer(Modifier.width(12.dp))
        Text(
            "ScholarVPN",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
        )
    }
}

/** 状态文案与圆点颜色 */
private fun phaseLabel(phase: VpnStatus.Phase): String = when (phase) {
    VpnStatus.Phase.IDLE -> "未连接"
    VpnStatus.Phase.CONNECTING -> "连接中…"
    VpnStatus.Phase.CONNECTED -> "已连接"
    VpnStatus.Phase.RECONNECTING -> "正在重连…"
    VpnStatus.Phase.FAILED -> "连接失败"
}

private fun phaseDotColor(phase: VpnStatus.Phase): Color = when (phase) {
    VpnStatus.Phase.IDLE -> Color(0xFF9E9EA7)
    VpnStatus.Phase.CONNECTING, VpnStatus.Phase.RECONNECTING -> Color(0xFFFFC24B)
    VpnStatus.Phase.CONNECTED -> Color(0xFF4ADE80)
    VpnStatus.Phase.FAILED -> Color(0xFFFF6B6B)
}

/** 渐变状态英雄卡：呼吸灯圆点 + 大状态文案 + Service 详细消息 + 当前服务器 */
@Composable
private fun StatusHero(
    phase: VpnStatus.Phase,
    message: String,
    busyServer: ServerEntry?,
) {
    val pulsing = phase == VpnStatus.Phase.CONNECTING ||
        phase == VpnStatus.Phase.CONNECTED || phase == VpnStatus.Phase.RECONNECTING

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(brandBrush())
            .padding(horizontal = 20.dp, vertical = 18.dp),
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                PulsingDot(color = phaseDotColor(phase), animate = pulsing)
                Spacer(Modifier.width(10.dp))
                Text(
                    phaseLabel(phase),
                    color = Color.White,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }
            if (message != phaseLabel(phase)) {
                Spacer(Modifier.height(4.dp))
                Text(
                    message,
                    color = Color.White.copy(alpha = 0.8f),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }
            if (busyServer != null) {
                Spacer(Modifier.height(12.dp))
                Surface(
                    shape = CircleShape,
                    color = Color.White.copy(alpha = 0.18f),
                ) {
                    Text(
                        busyServer.name.ifBlank { busyServer.ip },
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
                    )
                }
            }
        }
    }
}

/** 呼吸灯圆点（连接中/已连接时脉动） */
@Composable
private fun PulsingDot(color: Color, animate: Boolean) {
    val alpha = if (animate) {
        rememberInfiniteTransition(label = "pulse").animateFloat(
            initialValue = 0.4f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(900, easing = FastOutSlowInEasing)),
            label = "pulseAlpha",
        ).value
    } else 1f
    Box(
        modifier = Modifier
            .size(12.dp)
            .graphicsLayer { this.alpha = alpha }
            .clip(CircleShape)
            .background(color),
    )
}

/** 单张服务器卡片：头像圆标 / 名称 / IP:端口 · 传输 + 胶囊「连接/断开」按钮 + 编辑图标 */
@Composable
private fun ServerCard(
    entry: ServerEntry,
    selected: Boolean,
    /** 本卡正在连接/已连接：按钮变红色「断开」 */
    isBusyCard: Boolean,
    /** 本卡正在握手/重连：按钮内显示转圈 */
    connecting: Boolean,
    /** 其他卡忙碌：本卡连接按钮禁用 */
    otherBusy: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val shape = MaterialTheme.shapes.medium
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = !otherBusy, onClick = onSelect)
            .then(
                if (selected) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, shape)
                else Modifier.border(
                    1.dp,
                    MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f),
                    shape,
                )
            ),
        shape = shape,
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = if (selected)
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
            else MaterialTheme.colorScheme.surface,
        ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // 头像圆标：服务器名首字符
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .clip(CircleShape)
                    .background(
                        if (selected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.surfaceVariant
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    (entry.name.ifBlank { entry.ip }).take(1).uppercase(),
                    color = if (selected) MaterialTheme.colorScheme.onPrimary
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                )
            }
            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    entry.name.ifBlank { entry.ip },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    "${entry.ip}:${entry.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (entry.registerToken.isNotBlank()) {
                    Spacer(Modifier.height(5.dp))
                    Surface(
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.tertiaryContainer,
                    ) {
                        Text(
                            "待注册",
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        )
                    }
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                Button(
                    onClick = { if (isBusyCard) onDisconnect() else onConnect() },
                    // 授权未完成时首次点击先走授权流程
                    enabled = !otherBusy || isBusyCard,
                    shape = CircleShape,
                    colors = if (isBusyCard) ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ) else ButtonDefaults.buttonColors(),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 7.dp),
                ) {
                    if (connecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(15.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onError,
                        )
                        Spacer(Modifier.width(7.dp))
                    }
                    Text(if (isBusyCard) "断开" else "连接")
                }
                IconButton(
                    onClick = onEdit,
                    enabled = !otherBusy || isBusyCard,
                    modifier = Modifier.size(34.dp),
                ) {
                    Icon(
                        Icons.Outlined.Edit,
                        contentDescription = "编辑",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(19.dp),
                    )
                }
            }
        }
    }
}

/** 空状态：大圆 + 引导文案 + 「添加服务器」按钮 */
@Composable
private fun EmptyState(onAdd: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            modifier = Modifier
                .size(120.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Filled.Add,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(44.dp),
            )
        }
        Spacer(Modifier.height(20.dp))
        Text("还没有服务器", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(
            "添加你的第一台 VPN 服务器\n即可开始安全上网",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = onAdd,
            shape = CircleShape,
            contentPadding = PaddingValues(horizontal = 26.dp, vertical = 10.dp),
        ) {
            Text("添加服务器")
        }
    }
}

/** 添加 / 编辑服务器对话框（删除仅编辑已有卡片时出现；令牌/公钥/传输折叠在「高级选项」） */
@Composable
private fun ServerEditor(
    initial: ServerEntry?,
    onDismiss: () -> Unit,
    onSave: (ServerEntry) -> Unit,
    onDelete: (() -> Unit)?,
) {
    var name by rememberSaveable { mutableStateOf(initial?.name ?: "") }
    var ip by rememberSaveable { mutableStateOf(initial?.ip ?: "") }
    var port by rememberSaveable { mutableStateOf((initial?.port ?: 51820).toString()) }
    var useTcp by rememberSaveable { mutableStateOf(initial?.useTcp ?: false) }
    var clientId by rememberSaveable { mutableStateOf(initial?.clientId ?: "user") }
    var token by rememberSaveable { mutableStateOf(initial?.registerToken ?: "") }
    var pubKey by rememberSaveable { mutableStateOf(initial?.serverPubKey ?: "") }
    var advanced by rememberSaveable {
        mutableStateOf(initial?.let { it.registerToken.isNotBlank() || it.serverPubKey.isNotBlank() } ?: false)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = MaterialTheme.shapes.large,
        title = {
            Text(
                if (initial == null) "添加服务器" else "编辑服务器",
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("名称（可选）") }, singleLine = true,
                    shape = MaterialTheme.shapes.small,
                )
                OutlinedTextField(
                    value = ip, onValueChange = { ip = it.trim() },
                    label = { Text("服务器 IP（必填）") }, singleLine = true,
                    shape = MaterialTheme.shapes.small,
                )
                OutlinedTextField(
                    value = port, onValueChange = { port = it.filter { c -> c.isDigit() } },
                    label = { Text("端口") }, singleLine = true,
                    shape = MaterialTheme.shapes.small,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                OutlinedTextField(
                    value = clientId, onValueChange = { clientId = it.trim() },
                    label = { Text("ClientID") }, singleLine = true,
                    shape = MaterialTheme.shapes.small,
                )

                // 高级选项折叠头
                val chevron by animateFloatAsState(
                    targetValue = if (advanced) 180f else 0f,
                    animationSpec = tween(200, easing = FastOutSlowInEasing),
                    label = "chevron",
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(MaterialTheme.shapes.small)
                        .clickable { advanced = !advanced }
                        .padding(vertical = 6.dp, horizontal = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        Icons.Filled.ArrowDropDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.rotate(chevron),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "高级选项（令牌 / 公钥 / 传输）",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Medium,
                    )
                }

                AnimatedVisibility(visible = advanced) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedTextField(
                            value = token, onValueChange = { token = it.trim() },
                            label = { Text("注册令牌（留空=登录模式）") }, singleLine = true,
                            shape = MaterialTheme.shapes.small,
                        )
                        OutlinedTextField(
                            value = pubKey, onValueChange = { pubKey = it },
                            label = { Text("服务器公钥（server_sig.pub 原文）") },
                            minLines = 2,
                            shape = MaterialTheme.shapes.small,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Switch(checked = useTcp, onCheckedChange = { useTcp = it })
                            Spacer(Modifier.width(10.dp))
                            Text("TCP 传输（默认 UDP）", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSave(ServerEntry(
                        name = name, ip = ip.trim(),
                        port = port.toIntOrNull() ?: 51820,
                        useTcp = useTcp,
                        clientId = clientId.ifBlank { "user" },
                        registerToken = token,
                        serverPubKey = pubKey,
                    ))
                },
                enabled = ip.isNotBlank(),
                shape = CircleShape,
            ) { Text("保存") }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) {
                        Text("删除", color = MaterialTheme.colorScheme.error)
                    }
                }
                TextButton(onClick = onDismiss) { Text("取消") }
            }
        },
    )
}

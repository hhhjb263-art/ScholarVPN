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
import com.scholarvpn.client.ui.AgreementGate
import com.scholarvpn.client.ui.ScholarVpnTheme
import com.scholarvpn.client.vpn.ServerEntry
import com.scholarvpn.client.vpn.VpnSettings
import android.widget.Toast
import androidx.core.content.FileProvider
import com.scholarvpn.client.BuildConfig
import com.scholarvpn.client.service.MachineId
import com.scholarvpn.client.service.ServiceClient
import com.scholarvpn.client.service.ServiceException
import com.scholarvpn.client.update.UpdateChecker
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.rememberDrawerState
import com.scholarvpn.client.vpn.VpnStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import java.io.File

class MainActivity : ComponentActivity() {

    private var granted by mutableStateOf(false)
    private val servers = mutableStateListOf<ServerEntry>()

    private val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var updateState by mutableStateOf("")
    private var pendingUpdate by mutableStateOf<UpdateChecker.Policy?>(null)
    private var editingIndex by mutableStateOf<Int?>(null)
    private var activeIndex by mutableStateOf(0)

    private var svcState by mutableStateOf<VpnSettings.ServiceState?>(null)
    private var svcBusy by mutableStateOf(false)
    private var svcMsg by mutableStateOf("")
    private var pendingConnect by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        granted = VpnService.prepare(this) == null
        reloadServers()
        svcState = VpnSettings(this).loadServiceState()

        mainScope.launch {
            delay(300)
            if (!svcBusy) provisionManaged(refreshOnly = true)
        }

        val svcHeartbeat = android.os.Handler(android.os.Looper.getMainLooper())
        val svcTick = object : Runnable {
            override fun run() {
                if (!svcBusy) provisionManaged(refreshOnly = true)
                svcHeartbeat.postDelayed(this, 300_000L)
            }
        }
        svcHeartbeat.postDelayed(svcTick, 300_000L)
        setContent {
            ScholarVpnTheme {
                val drawerState = rememberDrawerState(DrawerValue.Closed)
                val drawerScope = rememberCoroutineScope()
                ModalNavigationDrawer(
                    drawerState = drawerState,
                    gesturesEnabled = true,
                    drawerContent = {
                        ModalDrawerSheet {
                            Spacer(Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .clip(MaterialTheme.shapes.small)
                                        .background(brandBrush()),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text("S", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                }
                                Spacer(Modifier.width(12.dp))
                                Column {
                                    Text("设置", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                    Text("ScholarVPN v" + BuildConfig.VERSION_NAME,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                            HorizontalDivider()
                            Spacer(Modifier.height(8.dp))

                            UpdateSection(
                                state = updateState,
                                hasUpdate = pendingUpdate != null,
                                onCheck = { checkUpdate() },
                                onUpdate = { pendingUpdate?.let { doUpdate(it) } },
                            )

                            ServiceSection(
                                state = svcState,
                                busy = svcBusy,
                                msg = svcMsg,
                                onProvision = { provisionManaged(refreshOnly = false) },
                                onRefresh = { provisionManaged(refreshOnly = true) },
                            )
                        }
                    },
                ) {
                LaunchedEffect(Unit) {
                    VpnStatus.tokenClearTick.collect { reloadServers() }
                }

                AgreementGate {
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

                        BrandHeader(onLogoClick = {
                            drawerScope.launch { drawerState.open() }
                        })

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
        }
    }

    override fun onResume() {
        super.onResume()
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

    private fun provisionManaged(refreshOnly: Boolean) {
        if (svcBusy) return
        svcBusy = true
        svcMsg = if (refreshOnly) "同步中..." else "申请中..."
        mainScope.launch(Dispatchers.IO) {
            try {
                val store = VpnSettings(this@MainActivity)
                val info = MachineId.collect(this@MainActivity)
                val st = store.loadServiceState()
                val creds = if (refreshOnly && !info.fp.isBlank()) {
                    try {
                        ServiceClient.fetchStatus(info.fp)
                    } catch (e: ServiceException) {
                        // 404 = 服务端无此设备记录，改走注册拿凭据
                        if (e.message?.contains("404") == true) ServiceClient.registerTrial(info)
                        else throw e
                    }
                } else {
                    ServiceClient.registerTrial(info)
                }

                store.saveServiceState(VpnSettings.ServiceState(
                    fp = creds.fp.ifBlank { info.fp },
                    clientId = creds.clientId,
                    token = creds.token.ifBlank { st?.token ?: "" },
                    status = creds.status,
                    expireAt = creds.expireAt,
                    quotaBytes = creds.quotaBytes,
                    usedBytes = creds.usedBytes,
                    limitKind = creds.limitKind,
                    remaining = creds.remaining,
                ))

                val verdict = ServiceClient.evaluate(
                    creds, System.currentTimeMillis() / 1000)
                if (verdict.blocked) {
                    pendingConnect = false
                    svcMsg = verdict.reason
                    svcState = store.loadServiceState()
                    return@launch
                }

                val list = try {
                    ServiceClient.fetchServerList(creds.fp.ifBlank { info.fp })
                } catch (e: Exception) {
                    reloadServers()
                    pendingConnect = false
                    svcMsg = "凭据已就绪，但拉取服务器列表失败：${e.message}"
                    svcState = store.loadServiceState()
                    return@launch
                }
                val n = store.applyManagedServers(
                    list.map { it.addr to it.pubkeyB64 },
                    creds.clientId,
                    creds.token.ifBlank { st?.token ?: "" },
                )
                reloadServers()
                svcMsg = "已就绪：$n 台服务器（${creds.clientId}）"
                svcState = store.loadServiceState()
                if (pendingConnect) {
                    pendingConnect = false
                    mainScope.launch { if (servers.isNotEmpty()) connectActive() }
                }
            } catch (e: Exception) {
                pendingConnect = false
                svcMsg = "失败：${e.message}"
            } finally {
                svcBusy = false
            }
        }
    }

    private fun checkUpdate() {
        updateState = "检查中..."
        mainScope.launch {
            try {
                val p = UpdateChecker.fetchPolicy()
                val prefs = getSharedPreferences("scholarvpn_update", MODE_PRIVATE)
                val installedSha = prefs.getString("installed_sha", "") ?: ""
                if (UpdateChecker.isNewer(p.latest, BuildConfig.VERSION_NAME) ||
                    UpdateChecker.hasNewPackage(installedSha, p.sha256)) {
                    if (p.url.isBlank()) {
                        pendingUpdate = null
                        updateState = "后台策略缺少 Android 下载地址"
                    } else {
                        pendingUpdate = p
                        updateState = "发现新版本 v${p.latest}，点击立即更新" +
                            (if (p.notes.isNotBlank()) "（${p.notes}）" else "")
                    }
                } else {
                    pendingUpdate = null
                    updateState = "已是最新版本 v" + BuildConfig.VERSION_NAME
                }
            } catch (e: Exception) {
                pendingUpdate = null
                updateState = "检查失败：${e.message}"
            }
        }
    }

    private fun doUpdate(p: UpdateChecker.Policy) {
        updateState = "准备下载..."
        mainScope.launch {
            try {
                val dir = File(cacheDir, "apk").apply { mkdirs() }
                val apk = File(dir, "ScholarVPN-${p.latest}.apk")
                UpdateChecker.downloadApk(p.url, p.sha256, p.size, apk) { pct ->
                    updateState = "下载中 $pct%"
                }
                updateState = "等待安装确认..."
                getSharedPreferences("scholarvpn_update", MODE_PRIVATE)
                    .edit().putString("installed_sha", p.sha256).apply()
                installApk(apk)
            } catch (e: Exception) {
                updateState = "更新失败：${e.message}"
            }
        }
    }

    private fun installApk(apk: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", apk)
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "无法打开安装器：${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun connectActive() {
        if (servers.isEmpty()) {
            pendingConnect = true
            svcMsg = "正在自动获取服务器…"
            if (!svcBusy) provisionManaged(refreshOnly = true)
            return
        }
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

@Composable
private fun ServiceSection(
    state: VpnSettings.ServiceState?,
    busy: Boolean,
    msg: String,
    onProvision: () -> Unit,
    onRefresh: () -> Unit,
) {
    HorizontalDivider()
    Spacer(Modifier.height(12.dp))
    Column(Modifier.padding(horizontal = 16.dp)) {
        Text("受管服务",
             style = MaterialTheme.typography.titleSmall,
             fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(6.dp))
        when {
            busy -> Text("处理中…",
                         style = MaterialTheme.typography.bodySmall,
                         color = MaterialTheme.colorScheme.onSurfaceVariant)
            state == null -> {
                Text("使用服务方提供的服务器（自动申请试用并下发列表）",
                     style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(8.dp))
                Button(onClick = onProvision, modifier = Modifier.fillMaxWidth()) {
                    Text("使用服务方服务器")
                }
            }
            else -> {
                Text(state.clientId,
                     style = MaterialTheme.typography.bodyMedium,
                     fontWeight = FontWeight.Medium)
                if (state.expireAt > 0) {
                    val remain = state.expireAt - System.currentTimeMillis() / 1000
                    val usedPct = if (state.quotaBytes > 0)
                        ((state.usedBytes * 100) / state.quotaBytes).coerceIn(0, 100) else 0
                    Text(
                        if (remain > 0)
                            "剩余 ${remain / 86400} 天 ${(remain % 86400) / 3600} 小时 · 已用 ${usedPct}%"
                        else "已到期",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (msg.isNotBlank()) {
                    Text(msg,
                         style = MaterialTheme.typography.bodySmall,
                         color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onRefresh, enabled = !busy) { Text("刷新") }
                    TextButton(onClick = onProvision, enabled = !busy) { Text("重新申请") }
                }
            }
        }
    }
}

@Composable
private fun brandBrush(): Brush {    return if (isSystemInDarkTheme()) {
        Brush.linearGradient(listOf(Color(0xFF3B47B0), Color(0xFF6B3FB8)))
    } else {
        Brush.linearGradient(listOf(Color(0xFF4C5BD4), Color(0xFF925BD4)))
    }
}

@Composable
private fun BrandHeader(onLogoClick: () -> Unit = {}) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .clip(MaterialTheme.shapes.small)
            .clickable { onLogoClick() },
    ) {
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

@Composable
private fun StatusHero(
    phase: VpnStatus.Phase,
    message: String,
    busyServer: ServerEntry?,
) {
    val pulsing = phase == VpnStatus.Phase.CONNECTING ||
        phase == VpnStatus.Phase.RECONNECTING

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

@Composable
private fun ServerCard(
    entry: ServerEntry,
    selected: Boolean,
    isBusyCard: Boolean,
    connecting: Boolean,
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
    var subnets by rememberSaveable { mutableStateOf(initial?.intranetSubnets ?: "") }
    var advanced by rememberSaveable {
        mutableStateOf(initial?.let {
            it.registerToken.isNotBlank() || it.serverPubKey.isNotBlank() ||
                it.intranetSubnets.isNotBlank()
        } ?: false)
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
                        "高级选项（令牌 / 公钥 / 传输 / 内网）",
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
                        if (initial?.managed == true) {
                            Text(
                                "受管服务器（由服务方下发）不支持内网访问，仅支持全局 / 智能分流。",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        } else {
                            OutlinedTextField(
                                value = subnets, onValueChange = { subnets = it },
                                label = { Text("内网网段（留空=全局代理）") },
                                placeholder = { Text("192.168.10.0/24,10.20.0.0/16") },
                                minLines = 2,
                                shape = MaterialTheme.shapes.small,
                            )
                            if (subnets.isNotBlank()) {
                                Text(
                                    "填写后只有这些网段走隧道，其余流量走本地网络，系统 DNS 不变。",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
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
                        intranetSubnets = if (initial?.managed == true) "" else subnets.trim(),
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

@Composable
private fun UpdateSection(
    state: String,
    hasUpdate: Boolean,
    onCheck: () -> Unit,
    onUpdate: () -> Unit,
) {
    Column(Modifier.padding(horizontal = 16.dp)) {
        Text("应用更新", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text(
            state.ifEmpty { "点击检查获取最新版本" },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = if (hasUpdate) onUpdate else onCheck) {
            Text(if (hasUpdate) "立即更新" else "检查更新")
        }
        Spacer(Modifier.height(8.dp))
    }
}

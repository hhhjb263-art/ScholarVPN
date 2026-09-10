package com.scholarvpn.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.scholarvpn.client.vpn.ServerEntry
import com.scholarvpn.client.vpn.VpnSettings
import com.scholarvpn.client.vpn.VpnStatus

/**
 * 主界面：服务器卡片列表（点卡片连接）+ 添加/编辑/删除 + 状态栏 + 断开。
 * TODO(M3)：连接中的旋转指示、卡片滑动删除、导入导出配置。
 */
class MainActivity : ComponentActivity() {

    private var granted by mutableStateOf(false)
    private val servers = mutableStateListOf<ServerEntry>()
    private var editingIndex by mutableStateOf<Int?>(null)   // null=关闭编辑器；-1=新增
    private var activeIndex by mutableStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        granted = VpnService.prepare(this) == null
        reloadServers()
        setContent {
            MaterialTheme {
                // Service 清令牌（注册成功消费/令牌失效作废）后自动刷新卡片，
                // 防止界面内存里的废令牌被编辑保存回存储（"连接后秒拒"的根因）
                LaunchedEffect(Unit) {
                    VpnStatus.tokenClearTick.collect { reloadServers() }
                }
                Surface(modifier = Modifier.fillMaxSize()) {
                    val phase by VpnStatus.phase.collectAsState()
                    val status by VpnStatus.message.collectAsState()
                    val busyIdx by VpnStatus.busyIndex.collectAsState()
                    val busy = VpnStatus.isBusy(phase)

                    Box(modifier = Modifier.fillMaxSize()) {
                        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                            Text("ScholarVPN", style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(4.dp))
                            Text("状态：$status", color = MaterialTheme.colorScheme.primary)

                            Spacer(Modifier.height(12.dp))
                            Box(modifier = Modifier.weight(1f)) {
                                if (servers.isEmpty()) {
                                    Text(
                                        "还没有服务器，点右下角 + 添加",
                                        modifier = Modifier.align(Alignment.Center),
                                        color = Color.Gray,
                                    )
                                } else {
                                    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                        itemsIndexed(servers) { index, s ->
                                            ServerCard(
                                                entry = s,
                                                selected = index == activeIndex,
                                                // 本卡正在连接/已连接（断开按钮渲染在本卡上）
                                                isBusyCard = busy && busyIdx == index,
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
                                    }
                                }
                            }
                        }

                        // 右下角 +：添加服务器
                        FloatingActionButton(
                            onClick = { editingIndex = -1 },
                            modifier = Modifier
                                .align(Alignment.BottomEnd)
                                .padding(16.dp),
                            containerColor = MaterialTheme.colorScheme.primary,
                        ) { Text("+") }
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

/** 单张服务器卡片：名称 / IP:端口 / 传输方式 + 卡内「连接」按钮，当前选中带描边 */
@Composable
private fun ServerCard(
    entry: ServerEntry,
    selected: Boolean,
    /** 本卡正在连接/已连接：按钮变红色「断开」 */
    isBusyCard: Boolean,
    /** 其他卡忙碌：本卡连接按钮禁用 */
    otherBusy: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = !otherBusy, onClick = onSelect)
            .then(
                if (selected) Modifier.border(
                    2.dp, MaterialTheme.colorScheme.primary,
                    MaterialTheme.shapes.medium)
                else Modifier
            ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(18.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    entry.name.ifBlank { entry.ip },
                    style = MaterialTheme.typography.titleLarge,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "${entry.ip}:${entry.port} · ${if (entry.useTcp) "TCP" else "UDP"}" +
                        if (entry.registerToken.isNotBlank()) " · 待注册" else "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.Gray,
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Button(
                    onClick = { if (isBusyCard) onDisconnect() else onConnect() },
                    // 授权未完成时首次点击先走授权流程
                    enabled = !otherBusy || isBusyCard,
                    colors = if (isBusyCard) ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error)
                    else ButtonDefaults.buttonColors(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(
                        horizontal = 18.dp, vertical = 6.dp),
                ) { Text(if (isBusyCard) "断开" else "连接") }
                TextButton(onClick = onEdit, enabled = !otherBusy || isBusyCard) { Text("编辑") }
            }
        }
    }
}

/** 添加 / 编辑服务器对话框（删除仅编辑已有卡片时出现） */
@Composable
private fun ServerEditor(
    initial: ServerEntry?,
    onDismiss: () -> Unit,
    onSave: (ServerEntry) -> Unit,
    onDelete: (() -> Unit)?,
) {
    var name by mutableStateOf(initial?.name ?: "")
    var ip by mutableStateOf(initial?.ip ?: "")
    var port by mutableStateOf((initial?.port ?: 51820).toString())
    var useTcp by mutableStateOf(initial?.useTcp ?: false)
    var clientId by mutableStateOf(initial?.clientId ?: "user")
    var token by mutableStateOf(initial?.registerToken ?: "")
    var pubKey by mutableStateOf(initial?.serverPubKey ?: "")

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial == null) "添加服务器" else "编辑服务器") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("名称（可选）") }, singleLine = true)
                OutlinedTextField(
                    value = ip, onValueChange = { ip = it.trim() },
                    label = { Text("服务器 IP（必填）") }, singleLine = true)
                OutlinedTextField(
                    value = port, onValueChange = { port = it.filter { c -> c.isDigit() } },
                    label = { Text("端口") }, singleLine = true)
                OutlinedTextField(
                    value = clientId, onValueChange = { clientId = it.trim() },
                    label = { Text("ClientID") }, singleLine = true)
                OutlinedTextField(
                    value = token, onValueChange = { token = it.trim() },
                    label = { Text("注册令牌（留空=登录模式）") }, singleLine = true)
                OutlinedTextField(
                    value = pubKey, onValueChange = { pubKey = it },
                    label = { Text("服务器公钥（server_sig.pub 原文）") }, minLines = 2)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = useTcp, onCheckedChange = { useTcp = it })
                    Text("TCP 传输（默认 UDP）")
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

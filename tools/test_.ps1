# ============================================================================
# probe_udp.ps1 —— ScholarVPN 服务端 UDP 连通性探测脚本
#   向目标 IP:Port 发送协议合法的 auth_hello（阶段1握手）报文，等待回包。
#   用于区分"服务器没起 / 端口错 / 防火墙静默丢弃"与"客户端代码问题"。
#
# 用法:
#   .\probe_udp.ps1                          # 默认测 38.76.208.163:51821
#   .\probe_udp.ps1 -Ip 1.2.3.4 -Port 51820
#   .\probe_udp.ps1 -Ip 1.2.3.4 -Ports 51820,51821 -TimeoutMs 5000
#   .\probe_udp.ps1 -Repeat 20 -IntervalMs 200   # 连发 20 轮，配合服务器 tcpdump 观察
#
# 判定:
#   - 收到 112 字节回包(魔数 4E 50 56 4D 01 09 ...) = 服务端正常，问题在客户端/回程
#   - 收到任意 UDP 回包                    = 端口有服务在响应，可进一步看内容
#   - 无回包但 TCP 22/80/443 通            = 主机在线，UDP 端口被防火墙/安全组静默丢弃
#   - TCP 也不通                           = 主机不可达/被墙/没开机
# ============================================================================
param(
    [string]$Ip = "38.76.208.163",
    [int[]]$Ports = @(51821),
    [int]$TimeoutMs = 5000,
    [int]$Repeat = 1,          # 每个端口连发几轮（配合服务器 tcpdump 观察用）
    [int]$IntervalMs = 200     # 每轮间隔
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function New-AuthHelloPacket {
    # 与 src/tunnel_protoco.h 一致：magic=0x4D56504E(LittleEndian) ver=1 type=8 payload_len=16 seq=0
    $hdr = [byte[]]@(
        0x4E, 0x50, 0x56, 0x4D,   # magic (LE)
        0x01,                     # version = v_udp
        0x08,                     # type = m_auth_hello
        0x00, 0x10,               # payload_len = 16 (network order)
        0x00, 0x00, 0x00, 0x00    # sequence = 0
    )
    $nonce = New-Object byte[] 16
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($nonce)
    return $hdr + $nonce
}

function Test-UdpPort([string]$ip, [int]$port, [int]$timeoutMs, [int]$repeat, [int]$intervalMs) {
    $packet = New-AuthHelloPacket
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $timeoutMs
        $udp.Connect($ip, $port)
        # 连发 repeat 轮 auth_hello（配合服务器 tcpdump 观察包是否到达）
        for ($i = 0; $i -lt $repeat; $i++) {
            [void]$udp.Send($packet, $packet.Length)
            if ($i -lt $repeat - 1) { Start-Sleep -Milliseconds $intervalMs }
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $reply = $udp.Receive([ref]$remote)
            $sw.Stop()
            $hex = ($reply | ForEach-Object { $_.ToString("X2") }) -join " "
            $isServerHello = $reply.Length -ge 12 -and
                $reply[0] -eq 0x4E -and $reply[1] -eq 0x50 -and
                $reply[2] -eq 0x56 -and $reply[3] -eq 0x4D -and
                $reply[5] -eq 0x01 -and $reply[6] -eq 0x09
            if ($isServerHello) {
                Write-Host ("  [OK] UDP {0}:{1} 收到合法 ServerHello ({2} 字节, {3}ms) → 服务端正常!" -f $ip, $port, $reply.Length, $sw.ElapsedMilliseconds)
            } else {
                Write-Host ("  [??] UDP {0}:{1} 收到 {2} 字节回包 ({3}ms) → 端口有服务但非本协议: {4}" -f $ip, $port, $reply.Length, $sw.ElapsedMilliseconds, $hex)
            }
            return $true
        } catch [System.Net.Sockets.SocketException] {
            $sw.Stop()
            $se = $_.Exception
            if ($se.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
                Write-Host ("  [!!] UDP {0}:{1} 收到 ICMP 端口不可达 → 主机在线但该 UDP 端口无服务监听" -f $ip, $port)
            } else {
                Write-Host ("  [XX] UDP {0}:{1} 无回包 (超时 {2}ms, {3}) → 静默丢弃/防火墙拦截/端口未监听" -f $ip, $port, $timeoutMs, $se.SocketErrorCode)
            }
            return $false
        }
    } finally {
        $udp.Close()
    }
}

function Test-TcpPort([string]$ip, [int]$port, [int]$timeoutMs) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($ip, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($timeoutMs)) {
            $tcp.EndConnect($iar)
            Write-Host ("  [OK] TCP {0}:{1} 可连接" -f $ip, $port)
            return $true
        }
        Write-Host ("  [XX] TCP {0}:{1} 连接超时" -f $ip, $port)
        return $false
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) { $msg = $_.Exception.InnerException.Message }
        Write-Host ("  [XX] TCP {0}:{1} 拒绝/不可达: {2}" -f $ip, $port, $msg)
        return $false
    } finally {
        $tcp.Close()
    }
}

Write-Host "=== 探测 $Ip ==="
Write-Host "-- UDP 协议探测 (auth_hello) --"
$udpOk = $false
foreach ($p in $Ports) {
    if (Test-UdpPort $Ip $p $TimeoutMs $Repeat $IntervalMs) { $udpOk = $true }
}
Write-Host "-- TCP 辅助探测 (判断主机是否在线) --"
$tcpOk = $false
foreach ($p in @(22, 80, 443)) {
    if (Test-TcpPort $Ip $p $TimeoutMs) { $tcpOk = $true }
}
Write-Host "-- 结论 --"
if ($udpOk) {
    Write-Host "服务端 UDP 可达 → 问题不在网络可达性，检查客户端日志/协议细节"
} elseif ($tcpOk) {
    Write-Host "主机在线但 UDP 无回包 → 大概率是云安全组/防火墙未放行 UDP $($Ports -join ',')，或服务端监听端口与探测端口不一致"
} else {
    Write-Host "主机基本不可达（TCP 也不通）→ 服务器关机/被墙/IP 变了"
}

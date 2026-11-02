#pragma once

// ============================================================================
// src/service/machine_id.h —— 机器指纹（受管服务试用模式）
//
// 隐私最小化设计（约束见 docs/受管服务与试用授权方案.md 2.2，老板拍板）：
//   - 指纹 = SHA-256(salt | 系统级设备标识)，规则 v2（2026-10-31 老板要求
//     「机器码必须是固定值」）：
//       Windows = 注册表 MachineGuid（系统安装时生成，重启/升级/换网卡/插拔
//                 外设都不变；仅重装系统会换 → 需重新申请试用）
//       Linux   = /etc/machine-id（同语义）
//   - os/cpu/ram/mac_hash 仅作后台人工核对的展示字段，【不参与指纹】——
//     MAC 会随有线/无线切换漂移、CPU/RAM 展示亦然，混入指纹会让同一台
//     机器变成"新设备"（v1 教训）
//   - 不采集：主机名、用户名、磁盘/主板序列号、软件列表、任何用户行为数据
//
// 用途边界：指纹是后台人工核对与防刷的"辅助"，不是防伪保证——系统镜像克隆
// 会带出相同 MachineGuid（两台机器同指纹），防刷主力是服务端公网 IP 限频 +
// 人工确认。
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>

namespace service {

struct MachineInfo {
    std::string fp;          // 64 位小写 hex 指纹（稳定，见文件头说明）
    std::string machine_id;  // 系统级设备标识原文（MachineGuid / machine-id）
    std::string os;          // 如 "Windows 11 build 22621 x64"（展示用，不参与指纹）
    std::string cpu;         // CPU 型号（明文，供后台人工核对）
    std::uint64_t ram_mb = 0;
    std::string mac_hash;    // MAC 集合的 SHA-256（核对辅助，可空，不参与指纹）
};

// 采集本机信息并计算指纹。
// 单字段采集失败时留空/置 0，整体仍成功（fp 退化为弱指纹）；
// 只有 SHA-256 本身失败才返回 fp 为空的结构。
MachineInfo collect_machine_info();

// 纯函数：由系统级设备标识计算指纹（可单测）。
std::string fingerprint_of(const std::string& machine_id);

// MAC 地址集合 → SHA-256 hex（内部统一小写去分隔符后排序去重再哈希；空集合返回空串）。
// 接受 "AA-BB-.." / "aa:bb:.." / "aabb.." 三种常见写法。
std::string hash_macs(const std::vector<std::string>& macs_any_format);

} // namespace service

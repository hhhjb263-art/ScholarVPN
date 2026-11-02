#pragma once

// ============================================================================
// src/service/service_bootstrap.h —— 受管服务接入点（发行版内置）
//
// 2026-10-31 老板拍板：受管功能随发行版内置，不是可配置项——用户选
// 「使用服务方服务器」必须开箱即用；只有「自建服务器」不需要它。
//
//   - kServiceBaseUrl   broker 前台地址（服务器上 nginx 把 /trial/ /svc/
//                       反代到本机 broker 18082）
//   - kServicePubKeyB64 service 签名公钥（SPKI DER base64，对应
//                       dist/keys-service/release.key 的公钥；
//                       私钥是服务信任根，丢了/泄露了要换钥重发版）
//
// config.ini [Service] ServiceURL / PublicKey 仍可覆盖内置值（测试与换址
// 迁移用），留空 = 用内置。自建分发的源码编译：把两个值置空即可让
// 「使用服务方」不可用。
// ============================================================================

namespace service {

inline constexpr char kServiceBaseUrl[] = "https://scholarvpn.homes:8445";
inline constexpr char kServicePubKeyB64[] =
    "MCowBQYDK2VwAyEAZqHN3GK6ZO5qp7eRAzkfcA5QQfUMZBFk8vLIPlMJpEQ=";

} // namespace service

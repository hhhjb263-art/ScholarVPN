cmake_minimum_required(VERSION 3.16)

project(VPN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 本项目仅支持 Linux（依赖 linux/if_tun.h、linux/route.h 等内核头文件）
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project only supports Linux")
endif()

# ============================================================
# 1) 模块静态库：把 Buffer / UDP / tun / LinuxAdapter / core 全部编入
# ============================================================
add_library(vpn_modules STATIC
    Buffer/PacketBuffer.cpp
    Buffer/QueueBuffer.cpp
    UDP/UDP.cpp
    TCP/tcpserver.cpp
    tun/tun.cpp
    LinuxAdapter/LinuxAdapter.cpp
    core/VpnCore.cpp
    Crypt/crypt.cpp
)

# 暴露所有头文件目录，方便各模块用 "PacketBuffer.h" 等直接包含
target_include_directories(vpn_modules PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Buffer
    ${CMAKE_CURRENT_SOURCE_DIR}/UDP
    ${CMAKE_CURRENT_SOURCE_DIR}/TCP
    ${CMAKE_CURRENT_SOURCE_DIR}/tun
    ${CMAKE_CURRENT_SOURCE_DIR}/LinuxAdapter
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/Crypt
)

# 线程（std::thread / std::mutex 需要链接 pthread）
find_package(Threads REQUIRED)
# 加密（X25519 / HKDF / AES-256-GCM）
find_package(OpenSSL REQUIRED)
target_link_libraries(vpn_modules PUBLIC Threads::Threads OpenSSL::Crypto)

# 编译告警
target_compile_options(vpn_modules PRIVATE -Wall -Wextra)

# ============================================================
# 2) 可执行文件 vpn_server（服务端入口）
# ============================================================
add_executable(vpn_server
    main.cpp
)
target_link_libraries(vpn_server PRIVATE vpn_modules)

# ============================================================
# 3) 中转（控制面）：admin_agent（VPN 服务器侧）+ vpn_controller（中转服务器）
#    只实现「VPN 服务器 ↔ 中转服务器」之间的业务接口（agent 通道）；
#    管理端客户端（Web/Qt）不在本次范围内。
#    两者共用 ServerAdmin/AdminWire.h 的线协议（长度前缀 JSON 帧；
#    传输层支持明文 TCP 兼容模式与 OpenSSL TLS 生产模式）。
# ============================================================
add_executable(admin_agent
    ServerAdmin/Agent.cpp
)
target_link_libraries(admin_agent PRIVATE vpn_modules OpenSSL::SSL)
target_compile_options(admin_agent PRIVATE -Wall -Wextra)

add_executable(vpn_controller
    ServerAdmin/Controller.cpp
)
target_link_libraries(vpn_controller PRIVATE vpn_modules OpenSSL::SSL)
target_compile_options(vpn_controller PRIVATE -Wall -Wextra)

# ============================================================
# 4) 本地管理服务 + 命令行客户端（各 VPN 服务器上运行）
#    admin_server：127.0.0.1:18080 的本地管理 API（公钥/IP/端口 + 令牌申请/查看/删除）
#    admin_cli   ：命令行调用上面这套 API（info/list/gen/del）
#    两者都自带 main()，是独立可执行；agent 转发时对接的正是 admin_server。
# ============================================================
add_executable(admin_server
    ServerAdmin/AdminServer.cpp
)
target_link_libraries(admin_server PRIVATE vpn_modules)

add_executable(admin_cli
    ServerAdmin/ServerAdminClinet.cpp
)
target_link_libraries(admin_cli PRIVATE vpn_modules)

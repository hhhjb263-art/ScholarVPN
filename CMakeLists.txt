cmake_minimum_required(VERSION 3.16)

project(ScholarVPNClient LANGUAGES CXX)

# ============================================================================
# Linux 客户端构建（Windows 继续用 VPN_.sln / VPN_.vcxproj，不走这里）
#
#   sudo apt install build-essential cmake qt6-base-dev libssl-dev
#   cmake -S . -B build-client
#   cmake --build build-client -j
#   sudo ./build-client/vpn_client
#
# 运行需要 root（或 CAP_NET_ADMIN）：创建 tun、改路由、改 DNS。
# 免 sudo 运行：
#   sudo setcap cap_net_admin+ep ./build-client/vpn_client
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR
        "本 CMake 工程只用于构建 Linux 客户端。Windows 请打开 VPN_.sln（MSVC + Qt6 msvc2022_64）。")
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(vpn_client
    Config.cpp
    Crypt.cpp

    src/UDP.cpp
    src/tcp.cpp
    src/packet_buffer.cpp
    src/PacketQueue.cpp
    src/logger.cpp
    src/reconnect_manager.cpp

    src/client/ClientApp.cpp

    src/platform/cfgstr.cpp
    src/platform/iplist.cpp
    src/update/update_policy.cpp
    src/update/update_fetcher.cpp
    src/update/update_checker.cpp
    src/update/update_install.cpp

    src/tun.cpp
    src/AdapterConfig.cpp
    src/route_manager.cpp
    src/DnsLeakGuard.cpp

    src/gui/AppBridge.cpp
    src/gui/QtWidgetsClass.cpp
    src/main.cpp
)

target_include_directories(vpn_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(vpn_client PRIVATE
    Threads::Threads
    OpenSSL::Crypto
    OpenSSL::SSL
    Qt6::Widgets
)

# 与 Windows 工程保持同样的告警级别；-Wno-unused-parameter 是因为接口签名
# （如 LinuxTun::init_tun 的 tunnelType）在 Linux 分支里用不到
target_compile_options(vpn_client PRIVATE -Wall -Wextra -Wno-unused-parameter)

install(TARGETS vpn_client RUNTIME DESTINATION bin)
install(FILES src/gui/style.qss DESTINATION bin)
install(FILES docs/routing/chnroute.txt DESTINATION bin)

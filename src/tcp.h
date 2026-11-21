#pragma once

#include "UDP.h"
#include <vector>

class TCP : public UDP
{
public:
    TCP(const char* remoteip, uint16_t port,
        bool is_running = false, size_t queueMax = 4096);

    uint8_t proto_version() const override;

protected:
    sock_t open_socket() override;
    bool establish() override;
    bool raw_send(const uint8_t* data, size_t len) override;
    bool recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                    size_t& pay_len, bool& got) override;

private:
    int take_frame(tunnel_header& hdr, const uint8_t*& payload, size_t& pay_len);
    void compact_rx();

    bool flush_tx_pending();

    std::vector<uint8_t> m_rxBuf;
    size_t m_rxOff = 0;
    size_t m_consumed = 0;

    std::vector<uint8_t> m_txPending;
    size_t m_txPendingOff = 0;
    uint32_t m_txBacklogLogged = 0;
};

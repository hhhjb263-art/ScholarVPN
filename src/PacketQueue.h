#pragma once

#include "packet_buffer.h"

#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstddef>

class PacketQueue
{
public:
	// pop_until 的返回值：取到数据 / 等到 deadline 仍无数据 / 队列已 shutdown
	enum class PopResult { Ok, Timeout, Shutdown };

	PacketQueue(size_t maxsize);
	~PacketQueue();
	bool push(packet_buffer&& buf);
	bool pop(packet_buffer& buf);
	// 带截止时间的弹出：队列空时最多等到 deadline（有数据/关闭立即返回）。
	// 供发送线程在"等数据"与"周期心跳"之间切换，替代固定 sleep 轮询
	PopResult pop_until(packet_buffer& buf, std::chrono::steady_clock::time_point deadline);
	bool try_pop(packet_buffer& buf); // 非阻塞弹出，无数据立即返回 false
	void shutdown();
	size_t size() const;
	bool empty() const;
private:
	size_t MaxSize;
	std::queue<packet_buffer> m_queue;
	mutable std::mutex m_mutex;
	std::condition_variable m_condition;
	bool m_shutdown{false};
};


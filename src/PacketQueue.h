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
	enum class PopResult { Ok, Timeout, Shutdown };

	PacketQueue(size_t maxsize);
	~PacketQueue();
	bool push(packet_buffer&& buf);
	bool pop(packet_buffer& buf);
	PopResult pop_until(packet_buffer& buf, std::chrono::steady_clock::time_point deadline);
	bool try_pop(packet_buffer& buf);
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

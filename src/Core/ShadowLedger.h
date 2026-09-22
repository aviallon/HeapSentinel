#pragma once

#include "Core/StackCapture.h"

#include <memory>

namespace hs
{
	enum AllocationFlags : std::uint32_t
	{
		kFlagLive = 1u << 0,
		kFlagSampled = 1u << 1,  // served from the guarded pool
		kFlagFreed = 1u << 2,
	};

	struct AllocationInfo
	{
		std::uintptr_t ptr = 0;
		std::size_t    size = 0;
		std::uint32_t  threadId = 0;
		std::uint32_t  flags = 0;
		void*          allocSite = nullptr;
		void*          freeSite = nullptr;
		std::uint32_t  allocStack = 0;  // index into the stack ring, 0 = none
		std::uint32_t  freeStack = 0;
	};

	// ptr -> AllocationInfo, sharded open addressing with linear probing.
	//
	// Deliberately boring: fixed capacity allocated once, one spinlock per
	// shard, no allocation after Init(), and fail-open everywhere. A sentinel
	// that breaks the game is worse than no sentinel, so when the table is
	// full or not ready every operation is a no-op and the hook passes through.
	class ShadowLedger
	{
	public:
		static ShadowLedger& Get();

		bool Init(std::size_t a_capacity, std::size_t a_shards, std::size_t a_stackDepth);
		void Shutdown();

		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		void Insert(std::uintptr_t a_ptr, const AllocationInfo& a_info);
		[[nodiscard]] bool Find(std::uintptr_t a_ptr, AllocationInfo& a_out) const;
		bool                Erase(std::uintptr_t a_ptr, AllocationInfo& a_out);

		[[nodiscard]] std::size_t Count() const;

		// Fixed ring of captured stacks. 0 is reserved for "none".
		[[nodiscard]] std::uint32_t StoreStack(const Stack& a_stack);
		[[nodiscard]] const Stack*  GetStack(std::uint32_t a_index) const;

	private:
		struct Entry
		{
			std::uintptr_t key = 0;  // 0 empty, 1 tombstone
			AllocationInfo info;
		};

		struct Shard
		{
			mutable std::atomic_flag lock{};
			std::unique_ptr<Entry[]> slots;
			std::size_t              capacity = 0;
			std::size_t              count = 0;

			void Lock() const
			{
				while (lock.test_and_set(std::memory_order_acquire)) {
					::YieldProcessor();
				}
			}
			void Unlock() const { lock.clear(std::memory_order_release); }
		};

		[[nodiscard]] Shard&       ShardFor(std::uintptr_t a_ptr);
		[[nodiscard]] const Shard& ShardFor(std::uintptr_t a_ptr) const;

		std::unique_ptr<Shard[]> _shards;
		std::size_t              _shardCount = 0;
		std::size_t              _shardCapacity = 0;

		std::unique_ptr<Stack[]> _stacks;
		std::size_t              _stackCount = 0;
		std::atomic<std::uint32_t> _stackCursor{ 1 };

		std::atomic<bool> _ready{ false };
	};
}

#pragma once

#include "Core/BloomFilter.h"
#include "Core/StackCapture.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#if defined(_MSC_VER)
#	include <intrin.h>  // _mm_pause for the bounded writer claim loop (HS_NO_PCH has no Windows.h)
#endif

namespace hs
{
	enum AllocationFlags : std::uint32_t
	{
		kFlagLive = 1u << 0,
		kFlagSampled = 1u << 1,    // served from the guarded pool
		kFlagFreed = 1u << 2,
		kFlagScaleform = 1u << 3,  // allocated by Scaleform's GMemoryHeapPT, not RE::MemoryManager
		kFlagPoisoned = 1u << 4,   // real free withheld; first qword overwritten with a poison address
		// Which hook family recorded the FIRST free. A double-free report carries
		// both families so a reader can tell a genuine second free (MM then MM,
		// say) from a nested observation of one logical free (SF then MM, the
		// EngineFixes-overridden-Scaleform path that produced the v0.3.0 flood).
		kFlagFreedByMM = 1u << 5,
		kFlagFreedBySF = 1u << 6,
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

		// Attribution fields (0.3.0). The first qword of the block is the
		// object's vtable once its constructor has run, so these three give the
		// freed-vs-corrupted discriminator:
		//   vtableAtAlloc   - first qword the instant the allocator returned it;
		//                     still pre-construction, so it is often garbage.
		//   vtableAtFree    - first qword just before we poisoned/freed it. This
		//                     is the object's real vtable at the moment it died.
		//   lastKnownVtable - last plausible vtable seen on a LIVE resource via
		//                     the GFxResourceWeakLib context hooks.
		// A freed block with a changed first qword is a use-after-free; a live
		// block whose first qword no longer matches lastKnownVtable is a stray
		// write into a live object (a different investigation).
		std::uintptr_t vtableAtAlloc = 0;
		std::uintptr_t vtableAtFree = 0;
		std::uintptr_t lastKnownVtable = 0;

		std::uint64_t allocTick = 0;  // GetTickCount64 at allocation
		std::uint64_t freeTick = 0;   // GetTickCount64 at free
		// 0.6.5: monotonic per-allocation instance id (0 = unknown). The free ring
		// never invalidates a record when an address is recycled, so the free
		// record and the watch slot carry this id and a free is matched to the
		// slot only when the two agree. See WatchpointEncoding.h.
		std::uint64_t allocInstance = 0;
		std::uint32_t poisonIndex = 0;  // 1-based quarantine slot, 0 = not poisoned
	};

	// Mint the next per-allocation instance id. Monotonic, never reused, and
	// starts at 1 so 0 stays reserved for "unknown". Called once per recorded
	// Scaleform allocation; lock-free (one relaxed fetch_add).
	[[nodiscard]] std::uint64_t NextAllocationInstance() noexcept;

	// ptr -> AllocationInfo, sharded open addressing with linear probing.
	//
	// LOCK-FREE BY CONSTRUCTION (0.3.0). Every entry carries a seqlock word
	// (the same VersionFor/SeqOfVersion/VersionIsWriting encoding used by
	// src/Ipc/ShmLayout.h and src/Ipc/ShmRing.cpp):
	//
	//   bit 0      : 1 while a writer owns the entry
	//   bits 63..1 : monotone sequence number
	//
	// A writer CASes an even version to odd (its claim), mutates the payload,
	// then release-publishes version + 2. A reader loads the version, skips an
	// odd entry, copies the payload, re-loads the version and rejects the copy
	// if it changed. A torn read therefore yields "unknown", never a wrong
	// record - and no reader, in particular not the VEH, ever takes a lock. A
	// handler that self-deadlocks on a lock the faulting thread already holds is
	// the one failure a diagnostic must never have.
	//
	// Writers are bounded and fail open: a 16-attempt CAS claim with a pause
	// between attempts, then the record is DROPPED and counted (WriterDrops).
	// A lossy run is legible rather than a stalled game thread. Userspace has no
	// preemption-disabled guarantee, so an unbounded spinlock here could burn a
	// whole scheduling quantum (worse under Wine, where sched_yield does not
	// reliably let the holder run, and across the two NUMA nodes of a 5950X).
	class ShadowLedger
	{
	public:
		static ShadowLedger& Get();

		bool Init(std::size_t a_capacity, std::size_t a_shards, std::size_t a_stackDepth);
		void Shutdown();

		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		void Insert(std::uintptr_t a_ptr, const AllocationInfo& a_info);
		// Lock-free: safe to call from the vectored exception handler.
		[[nodiscard]] bool Find(std::uintptr_t a_ptr, AllocationInfo& a_out) const;
		bool                Erase(std::uintptr_t a_ptr, AllocationInfo& a_out);

		[[nodiscard]] std::size_t Count() const;

		// Inserts that could not be placed because the probe window was full of
		// live entries. A non-zero and growing value means the ledger is
		// saturating and recording has stopped for new allocations.
		[[nodiscard]] std::uint64_t InsertFailures() const { return _insertFailures.load(std::memory_order_relaxed); }

		// Writer claims abandoned after the bounded pause loop (entry contended).
		// Distinct from InsertFailures: the table may have had room, but the
		// entry was busy. Both are surfaced in the 60 s stats line.
		[[nodiscard]] std::uint64_t WriterDrops() const { return _writerDrops.load(std::memory_order_relaxed); }

		// Effective table size, so "the ledger the game actually runs" cannot be
		// silently different from the one the operator thinks they configured
		// (a deployed ini overrides the compiled default).
		[[nodiscard]] std::size_t Capacity() const { return _shardCount * _shardCapacity; }

		// Bloom pre-filter accounting. The filter is queried before any probe, so
		// the VEH's overwhelmingly-common "not ours" case is a single relaxed load
		// with no seqlock and no probing. It is sized to the table capacity and
		// non-aging here, so a miss is authoritative and never hides a record the
		// ledger still holds.
		[[nodiscard]] std::size_t   BloomBytes() const { return _bloom.Bytes(); }
		[[nodiscard]] std::uint64_t BloomSwaps() const { return _bloom.Swaps(); }

		// Fixed ring of captured stacks. 0 is reserved for "none".
		[[nodiscard]] std::uint32_t StoreStack(const Stack& a_stack);
		[[nodiscard]] const Stack*  GetStack(std::uint32_t a_index) const;

	private:
		// Portable CPU relax for the bounded writer claim loop. The plugin runs
		// on x64 Windows; the off-game tests also build on aarch64, where there
		// is no pause instruction and a compiler fence is sufficient.
		static void Relax()
		{
#if defined(_MSC_VER)
			_mm_pause();
#elif defined(__i386__) || defined(__x86_64__)
			__builtin_ia32_pause();
#else
			std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
		}

		struct Entry
		{
			std::atomic<std::uint64_t> version{};  // seqlock: bit0 = writer owns it
			std::uintptr_t             key = 0;    // 0 empty, 1 tombstone
			AllocationInfo             info;
		};

		struct Shard
		{
			std::unique_ptr<Entry[]>      slots;
			std::size_t                   capacity = 0;
			std::atomic<std::size_t>      count{ 0 };
		};

		[[nodiscard]] Shard&       ShardFor(std::uintptr_t a_ptr);
		[[nodiscard]] const Shard& ShardFor(std::uintptr_t a_ptr) const;

		// Bounded claim. Returns false (and bumps _writerDrops) when the entry
		// stays busy for the whole pause loop.
		[[nodiscard]] static bool Claim(Entry& a_entry, std::atomic<std::uint64_t>& a_drops);
		static void               Publish(Entry& a_entry, std::uint64_t a_claimedVersion);

		// Prefer a tombstone; otherwise evict the oldest FREE entry (bounded
		// quarantine), else fail open. Durable Scaleform-free provenance lives in
		// the separately-budgeted ScaleformFreeRing, not here, so the main table's
		// eviction policy cannot starve engine allocations.
		void InsertAtVictim(std::uintptr_t a_ptr, const AllocationInfo& a_info, std::size_t a_index, bool a_tombstone, bool a_mayEvictFreed);

		std::unique_ptr<Shard[]> _shards;
		std::size_t              _shardCount = 0;
		std::size_t              _shardCapacity = 0;

		std::unique_ptr<Stack[]> _stacks;
		std::size_t              _stackCount = 0;
		BloomFilter              _bloom;
		std::atomic<std::uint32_t> _stackCursor{ 1 };
		std::atomic<std::uint64_t> _insertFailures{ 0 };
		std::atomic<std::uint64_t> _writerDrops{ 0 };

		std::atomic<bool> _ready{ false };
	};
}
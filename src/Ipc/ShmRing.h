#pragma once

// The hot ring: a lock-free, overwriting, per-thread trace buffer living in the
// shared mapping. The game process produces, the detached helper consumes, and
// because the buffer lives in shared memory the helper can still dump the whole
// pre-crash window at full resolution after the game has died.
//
// Design points that matter, each of which is covered by a test in tests/:
//
//  * ONE PRODUCER PER RING. Every allocating thread claims its own ring from
//    the registry, so the hot path is a plain store plus a release store: no
//    CAS, no lock, no contention. A single shared MPMC ring was rejected on
//    purpose - with fetch_add-assigned positions a producer that gets
//    preempted publishes out of order, and a consumer that follows slot
//    identities can then be dragged backwards or lose a record it already
//    passed. Per-thread rings make ordering exact by construction.
//
//  * THE PRODUCER NEVER BLOCKS AND NEVER FAILS. When a ring is full the oldest
//    record is simply overwritten and the consumer counts the gap. A tracer
//    that can stall the game thread is worse than a lossy tracer.
//
//  * A TORN RECORD CANNOT BE ACCEPTED. Each slot carries a seqlock word that
//    goes odd before the payload is touched and even after it is published, and
//    the consumer checks it on both sides of the copy. A producer that dies
//    mid-record leaves the word odd forever, and the consumer defers that ring
//    rather than reading a half-written record.
//
//  * DEFERRED IS NOT DROPPED. A slot that is being written right now stops the
//    drain of that ring and is retried on the next pass. With one ring per
//    thread a slow producer therefore costs nothing.
//
//  * ORDERING MODEL. The seqlock double-check relies on x86-64 TSO (stores are
//    not reordered with stores, loads not with loads), which is the only target
//    here, plus a compiler barrier around the payload copy. Making the payload
//    accesses relaxed atomics would be needed to claim portability to a
//    weakly-ordered target; that is deliberately not claimed.

#include "Ipc/ShmLayout.h"

#include <cstdint>
#include <cstring>

namespace hs::ipc
{
	// --- raw accessors over a mapped region ---------------------------------

	[[nodiscard]] inline std::uint8_t* RegionBase(void* a_base) noexcept
	{
		return static_cast<std::uint8_t*>(a_base);
	}

	[[nodiscard]] inline ShmHeader& HeaderAt(void* a_base) noexcept
	{
		return *reinterpret_cast<ShmHeader*>(RegionBase(a_base) + 0);
	}

	[[nodiscard]] inline RingHeader& RingAt(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring) noexcept
	{
		auto* rings = reinterpret_cast<RingHeader*>(RegionBase(a_base) + a_layout.ringHeaderOffset);
		return rings[a_ring];
	}

	[[nodiscard]] inline Slot* SlotsAt(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring) noexcept
	{
		return reinterpret_cast<Slot*>(RegionBase(a_base) + a_layout.RingSlotsOffset(a_ring));
	}

	// Record ids start at kFirstSeq, so the slot index is (seq - kFirstSeq).
	[[nodiscard]] inline Slot* SlotAt(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring, std::uint64_t a_seq) noexcept
	{
		return SlotsAt(a_base, a_layout, a_ring) + ((a_seq - kFirstSeq) % a_layout.slotCountPerRing);
	}

	// --- session setup ------------------------------------------------------

	// Prepares a freshly created (and therefore zero-filled) region. Only the
	// creator calls this; an attacher validates instead.
	void InitialiseSession(
		void*             a_base,
		const ShmLayout&  a_layout,
		std::uint64_t     a_sessionId,
		std::uint32_t     a_gamePid,
		std::uint64_t     a_createdAtUnix,
		std::uint64_t     a_createdAtTick,
		std::uint64_t     a_tickFrequency,
		std::uint32_t     a_samplePrime);

	// --- ring ownership -----------------------------------------------------

	// Claims a ring for `a_threadId`: the first free one, or - only when
	// a_staleTicks is non-zero - one whose owner has been silent for longer
	// than that, which is how a thread that exited without releasing (or was
	// killed) gets its ring back. Returns -1 when every ring is busy, which the
	// caller must treat as "drop this record and say so", never as "block".
	[[nodiscard]] std::int32_t ClaimRing(
		void*             a_base,
		const ShmLayout&  a_layout,
		std::uint64_t     a_threadId,
		std::uint64_t     a_nowTick,
		std::uint64_t     a_staleTicks) noexcept;

	// Releases a ring back to the pool. Ignores a ring it does not own, so a
	// late release after a takeover cannot steal someone else's ring.
	void ReleaseRing(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring, std::uint64_t a_threadId) noexcept;

	// --- producer -----------------------------------------------------------

	// The producer half. One instance per allocating thread; it owns exactly
	// one ring and never touches another thread's.
	class RingProducer
	{
	public:
		static constexpr std::uint32_t kNoRing = 0xFFFFFFFFu;

		RingProducer() = default;
		~RingProducer() = default;
		RingProducer(const RingProducer&) = delete;
		RingProducer& operator=(const RingProducer&) = delete;

		// Claims a ring for this producer. Safe to call again after a failure.
		[[nodiscard]] bool Claim(void* a_base, const ShmLayout& a_layout, std::uint64_t a_threadId, std::uint64_t a_nowTick, std::uint64_t a_staleTicks) noexcept;

		// Hands the ring back (thread exit, plugin shutdown).
		void Release(void* a_base, const ShmLayout& a_layout) noexcept;

		[[nodiscard]] bool          Owned() const noexcept { return _ring != kNoRing; }
		[[nodiscard]] std::uint32_t RingIndex() const noexcept { return _ring; }
		[[nodiscard]] std::uint64_t Published() const noexcept { return _published; }

		// Publishes one record. Never blocks, never allocates, never fails.
		// `a_event.tick` is used as the ring's last-active tick, so no extra
		// clock read happens on the hot path. If the ring was reclaimed while
		// this thread was idle the producer re-claims silently (or drops the
		// record when every ring is busy), so a producer can never end up
		// writing into another thread's ring.
		void Publish(void* a_base, const ShmLayout& a_layout, const ShmEvent& a_event) noexcept;

	private:
		std::uint32_t _ring = kNoRing;
		std::uint64_t _threadId = 0;
		std::uint64_t _published = 0;
		std::uint64_t _staleTicks = 0;
		std::uint64_t _lastTouchTick = 0;
	};

	// --- consumer -----------------------------------------------------------

	struct DrainStats
	{
		std::uint64_t consumed = 0;
		std::uint64_t dropped = 0;        // records overwritten before we saw them
		std::uint64_t deferredRings = 0;  // rings that stopped at an in-flight slot
	};

	// Called once per complete record. `a_ring` is the producing ring, which
	// the helper uses to attribute the record to a thread.
	using EventSink = void (*)(void* a_context, std::uint32_t a_ring, const ShmEvent& a_event);

	// Drains every ring once. Non-blocking: it stops a ring at the first slot
	// that is currently being written and returns, so the caller can poll at
	// its own pace and a stalled producer never wedges the helper. The
	// session-level consumed/dropped counters are updated here.
	DrainStats DrainAll(void* a_base, const ShmLayout& a_layout, EventSink a_sink, void* a_context) noexcept;

	// Drains a single ring, for tests and for the post-mortem path that wants
	// one ring at a time.
	DrainStats DrainRing(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring, EventSink a_sink, void* a_context) noexcept;
}

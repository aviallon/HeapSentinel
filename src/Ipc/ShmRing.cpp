// Deliberately does not include PCH.h. tests/ compiles this file on Linux, where
// Windows.h and CommonLibSSE-NG do not exist, so that the ring protocol is
// verified off-game on a second toolchain. The plugin build defines nothing
// extra; the test build defines HS_NO_PCH.
#ifndef HS_NO_PCH
#	include "PCH.h"
#endif

#include "Ipc/ShmRing.h"

#include <atomic>

namespace hs::ipc
{
	namespace
	{
		// The ring's liveness tick is only used for stale reclamation, which
		// works on a timescale of seconds, so refreshing it every few thousand
		// records is plenty and keeps a store off most publishes.
		constexpr std::uint64_t kTouchInterval = 4096;

		// Starts a fresh generation on a ring. The consumer re-reads readSeq
		// from the header, so resetting both cursors is enough for it to see
		// "nothing pending" rather than a stale backlog. The generation is
		// bumped LAST and with a release store: a consumer that observes the new
		// generation is guaranteed to observe the reset cursors too, and a
		// consumer that was mid-drain when this happened will see the generation
		// change and decline to write its stale readSeq back.
		void BeginGeneration(RingHeader& a_ring, std::uint64_t a_nowTick) noexcept
		{
			StoreRelaxed(a_ring.writeSeq, 0);
			StoreRelaxed(a_ring.readSeq, 0);
			StoreRelaxed(a_ring.drops, 0);
			StoreRelaxed(a_ring.lastActiveTick, a_nowTick);
			StoreRelaxed(a_ring.claimedAtTick, a_nowTick);
			StoreRelease(a_ring.generation, LoadRelaxed(a_ring.generation) + 1);
		}
	}

	void InitialiseSession(
		void*            a_base,
		const ShmLayout& a_layout,
		std::uint64_t    a_sessionId,
		std::uint32_t    a_gamePid,
		std::uint64_t    a_createdAtUnix,
		std::uint64_t    a_createdAtTick,
		std::uint64_t    a_tickFrequency,
		std::uint32_t    a_samplePrime)
	{
		auto& header = HeaderAt(a_base);
		std::memset(&header, 0, sizeof(ShmHeader));

		header.magic = kShmMagic;
		header.layoutVersion = kShmLayoutVersion;
		header.headerSize = static_cast<std::uint32_t>(sizeof(ShmHeader));
		header.totalSize = a_layout.totalBytes;
		header.sessionId = a_sessionId;
		header.gamePid = a_gamePid;
		header.hostPid = 0;
		header.createdAtUnix = a_createdAtUnix;
		header.createdAtTick = a_createdAtTick;
		header.tickFrequency = a_tickFrequency;

		header.heartbeatSeq = 0;
		header.heartbeatTick = a_createdAtTick;
		header.gameState = static_cast<std::uint64_t>(GameState::kInit);

		header.ringHeaderOffset = a_layout.ringHeaderOffset;
		header.ringCount = kMaxRings;
		header.slotCountPerRing = a_layout.slotCountPerRing;
		header.slotsBytesPerRing = a_layout.slotsBytesPerRing;

		header.memcacheOffset = a_layout.memcacheOffset;
		header.memcacheBytes = a_layout.memcacheBytes;
		header.memcacheShards = 0;
		header.memcacheSlotBytes = 0;

		header.samplePrime = a_samplePrime;
		header.healthState = static_cast<std::uint32_t>(HealthState::kUnknown);

		for (std::uint32_t i = 0; i < kMaxRings; ++i) {
			auto& ring = RingAt(a_base, a_layout, i);
			std::memset(&ring, 0, sizeof(RingHeader));
			ring.slotsOffset = a_layout.RingSlotsOffset(i);
			ring.capacity = a_layout.slotCountPerRing;
		}
	}

	std::int32_t ClaimRing(
		void*            a_base,
		const ShmLayout& a_layout,
		std::uint64_t    a_threadId,
		std::uint64_t    a_nowTick,
		std::uint64_t    a_staleTicks) noexcept
	{
		if (a_threadId == 0) {
			// 0 is the encoding for "free", so a caller without a thread id can
			// never own a ring. Refuse rather than corrupt the registry.
			return -1;
		}

		std::int32_t staleCandidate = -1;

		for (std::uint32_t i = 0; i < kMaxRings; ++i) {
			auto& ring = RingAt(a_base, a_layout, i);

			const std::uint64_t owner = LoadAcquire(ring.ownerThread);

			if (owner == 0) {
				std::uint64_t expected = 0;
				if (!CompareExchange(ring.ownerThread, expected, a_threadId)) {
					continue;  // lost the race; the next ring is just as good
				}
				BeginGeneration(ring, a_nowTick);
				return static_cast<std::int32_t>(i);
			}

			if (owner == a_threadId) {
				// This thread already owns a ring. Refusing is the safe answer:
				// handing back the same ring would silently make two producers
				// share one buffer, which is the one thing the design forbids.
				return -1;
			}

			if (staleCandidate < 0 && a_staleTicks > 0) {
				const std::uint64_t last = LoadRelaxed(ring.lastActiveTick);
				if (a_nowTick > last && (a_nowTick - last) > a_staleTicks) {
					staleCandidate = static_cast<std::int32_t>(i);
				}
			}
		}

		// Every ring is busy. Only now is it worth taking one away from an owner
		// that has been silent for longer than the staleness window - a thread
		// that exited without releasing, or was killed.
		if (staleCandidate >= 0) {
			auto& ring = RingAt(a_base, a_layout, static_cast<std::uint32_t>(staleCandidate));
			std::uint64_t owner = LoadAcquire(ring.ownerThread);
			if (owner != 0 && owner != a_threadId) {
				if (CompareExchange(ring.ownerThread, owner, a_threadId)) {
					BeginGeneration(ring, a_nowTick);
					return staleCandidate;
				}
			}
		}

		return -1;
	}

	void ReleaseRing(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring, std::uint64_t a_threadId) noexcept
	{
		if (a_ring >= kMaxRings) {
			return;
		}
		auto& ring = RingAt(a_base, a_layout, a_ring);
		// The compare-exchange is what makes a late release harmless: if the
		// ring was taken over while this thread was away, `expected` no longer
		// matches and nothing happens. A failed exchange is the expected
		// outcome there, so the result is deliberately ignored.
		std::uint64_t expected = a_threadId;
		(void)CompareExchange(ring.ownerThread, expected, 0);
	}

	bool RingProducer::Claim(
		void*            a_base,
		const ShmLayout& a_layout,
		std::uint64_t    a_threadId,
		std::uint64_t    a_nowTick,
		std::uint64_t    a_staleTicks) noexcept
	{
		if (Owned()) {
			return true;
		}

		const auto ring = ClaimRing(a_base, a_layout, a_threadId, a_nowTick, a_staleTicks);
		if (ring < 0) {
			return false;
		}

		_ring = static_cast<std::uint32_t>(ring);
		_threadId = a_threadId;
		_staleTicks = a_staleTicks;
		_published = LoadRelaxed(RingAt(a_base, a_layout, _ring).writeSeq);
		_lastTouchTick = a_nowTick;
		return true;
	}

	void RingProducer::Release(void* a_base, const ShmLayout& a_layout) noexcept
	{
		if (!Owned()) {
			return;
		}
		ReleaseRing(a_base, a_layout, _ring, _threadId);
		_ring = kNoRing;
	}

	void RingProducer::Publish(void* a_base, const ShmLayout& a_layout, const ShmEvent& a_event) noexcept
	{
		if (!Owned()) {
			return;
		}

		RingHeader* ring = &RingAt(a_base, a_layout, _ring);

		// The ring can be reclaimed out from under us if it had been silent for
		// longer than the staleness window while every other ring was busy.
		// Checking is one relaxed load from a cache line this call already
		// touches, so it is free; publishing into someone else's ring is not.
		if (LoadRelaxed(ring->ownerThread) != _threadId) {
			_ring = kNoRing;
			if (!Claim(a_base, a_layout, _threadId, a_event.tick, _staleTicks)) {
				return;  // every ring is busy: drop this record rather than stall
			}
			ring = &RingAt(a_base, a_layout, _ring);
		}

		const std::uint64_t seq = _published + 1;
		Slot*               slot = SlotAt(a_base, a_layout, _ring, seq);

		// Invalidate first. A consumer that looks at this slot now sees "being
		// written" and defers the whole ring, so it can never accept a
		// half-written record - not even if this thread never gets to publish.
		StoreRelaxed(slot->version, VersionFor(seq, true));

		// The payload copy must not be hoisted above the invalidate, nor sunk
		// below the publish. atomic_signal_fence is a pure compiler barrier: it
		// costs nothing at run time, and x86-64 TSO supplies the hardware
		// ordering (see the note at the top of ShmRing.h).
		std::atomic_signal_fence(std::memory_order_seq_cst);

		ShmEvent record = a_event;
		record.seq = seq;
		std::memcpy(&slot->event, &record, sizeof(ShmEvent));

		std::atomic_signal_fence(std::memory_order_seq_cst);

		StoreRelease(slot->version, VersionFor(seq, false));
		StoreRelease(ring->writeSeq, seq);

		_published = seq;

		if ((seq % kTouchInterval) == 0) {
			StoreRelaxed(ring->lastActiveTick, a_event.tick);
			_lastTouchTick = a_event.tick;
		}

		// Note what is deliberately absent: no session-level counter is touched
		// here. A single shared "events produced" counter would ping-pong one
		// cache line across every allocating thread; the helper derives the
		// aggregate from the per-ring writeSeq values instead.
	}

	DrainStats DrainRing(void* a_base, const ShmLayout& a_layout, std::uint32_t a_ring, EventSink a_sink, void* a_context) noexcept
	{
		DrainStats stats;
		if (a_ring >= kMaxRings) {
			return stats;
		}

		auto& ring = RingAt(a_base, a_layout, a_ring);

		// readSeq is re-read from the header rather than cached in the consumer,
		// so a ring that was reclaimed (and reset) is picked up with no
		// out-of-band notification, and the consumer survives its own restart.
		std::uint64_t expect = LoadAcquire(ring.readSeq) + kFirstSeq;
		const std::uint64_t generation = LoadAcquire(ring.generation);

		for (;;) {
			const std::uint64_t written = LoadAcquire(ring.writeSeq);
			if (expect > written) {
				break;
			}

			Slot* slot = SlotAt(a_base, a_layout, a_ring, expect);

			const std::uint64_t v1 = LoadAcquire(slot->version);
			if (VersionIsWriting(v1)) {
				// Being written right now, or abandoned mid-record by a
				// producer that died. Defer the ring; never read the payload.
				++stats.deferredRings;
				break;
			}

			const std::uint64_t record = SeqOfVersion(v1);
			if (record != expect) {
				if (record > expect) {
					// The producer wrapped past us: everything in between is
					// gone, and the gap is reported rather than hidden.
					stats.dropped += (record - expect);
					expect = record;
					continue;
				}
				// A slot from a previous generation. Nothing to read.
				++stats.dropped;
				++expect;
				continue;
			}

			ShmEvent event;
			std::atomic_signal_fence(std::memory_order_seq_cst);
			std::memcpy(&event, &slot->event, sizeof(ShmEvent));
			std::atomic_signal_fence(std::memory_order_seq_cst);

			const std::uint64_t v2 = LoadAcquire(slot->version);
			if (v1 != v2) {
				// Overwritten while we were copying it: the record is torn, so
				// it is dropped rather than interpreted.
				++stats.dropped;
				++expect;
				continue;
			}

			if (a_sink != nullptr) {
				a_sink(a_context, a_ring, event);
			}
			++stats.consumed;
			++expect;
		}

		// Write the progress back only if the ring was not reclaimed while we
		// were draining it; otherwise this would resurrect a stale cursor.
		if (LoadAcquire(ring.generation) == generation) {
			StoreRelease(ring.readSeq, expect - kFirstSeq);
			StoreRelaxed(ring.drops, LoadRelaxed(ring.drops) + stats.dropped);
		}

		return stats;
	}

	DrainStats DrainAll(void* a_base, const ShmLayout& a_layout, EventSink a_sink, void* a_context) noexcept
	{
		DrainStats total;
		for (std::uint32_t i = 0; i < kMaxRings; ++i) {
			const DrainStats stats = DrainRing(a_base, a_layout, i, a_sink, a_context);
			total.consumed += stats.consumed;
			total.dropped += stats.dropped;
			total.deferredRings += stats.deferredRings;
		}

		if (total.consumed != 0 || total.dropped != 0) {
			auto& header = HeaderAt(a_base);
			if (total.consumed != 0) {
				(void)FetchAddRelaxed(header.eventsConsumed, total.consumed);
			}
			if (total.dropped != 0) {
				(void)FetchAddRelaxed(header.eventsDropped, total.dropped);
			}
		}

		return total;
	}
}

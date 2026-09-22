#pragma once

// Fixed, versioned, pointer-free shared-memory layout, mapped by both
// HeapSentinel.dll (the game process) and HeapSentinelHost.exe (the detached
// helper that owns the database and therefore survives a game crash).
//
// The rules this header exists to enforce:
//
//  * Every cross-process field is a plain fixed-width integer. No pointers, no
//    vtables, no std:: containers, no allocation inside the mapping. The two
//    processes may map the region at different base addresses, so anything
//    address-like is stored as an OFFSET from the mapping base.
//
//  * Atomicity comes from std::atomic_ref over those plain integers, not from
//    std::atomic members. That keeps the layout POD and byte-identical across
//    compilers and processes - which is what makes the static_asserts below
//    mean anything - and it is precisely the use case atomic_ref is specified
//    for. It also means both sides must be built with a lock-free uint64_t,
//    which is asserted rather than assumed.
//
//  * kShmLayoutVersion is part of the contract. A mismatch must be refused
//    loudly by both sides and never reinterpreted: a helper built against a
//    different layout reading this region would misread every single field,
//    silently.
//
// Nothing in this header (or in ShmRing/Sampling) may include Windows.h or
// PCH.h: tests/ compiles these files on Linux as well, so that the ring
// protocol is verified off-game on a second toolchain.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace hs::ipc
{
	// "HELLOSEN"
	inline constexpr std::uint64_t kShmMagic = 0x48454C4C4F53454Eull;

	// Bump whenever any struct in this file changes shape. Both sides compare
	// it and refuse to run together if it differs.
	inline constexpr std::uint32_t kShmLayoutVersion = 1;

	// One hot ring per allocating thread, claimed lazily. Bounded because the
	// registry lives in shared memory and the consumer walks it linearly.
	inline constexpr std::uint32_t kMaxRings = 64;

	// Record ids start at 1 so that a zero-filled slot (version == 0) is
	// unambiguously "never written" rather than "record 0".
	inline constexpr std::uint64_t kFirstSeq = 1;

	enum class EventKind : std::uint32_t
	{
		kNone = 0,
		kAlloc = 1,
		kFree = 2,
		kRealloc = 3,
		kReport = 4,   // a detection fired; aux = report id
		kMarker = 5,   // session milestone (module map complete, config reloaded, ...)
		kHealth = 6,   // health-state transition
	};

	// Why a record was kept even though the sampler would have dropped it.
	// Persisted alongside the event so the database can answer "why do I have
	// this record?" without re-deriving it.
	enum EventFlags : std::uint32_t
	{
		kFlagNone = 0,
		kFlagSampled = 1u << 0,   // passed the deterministic per-pointer sampler
		kFlagWatchSite = 1u << 1, // caller is on the configured watchlist
		kFlagLongLived = 1u << 2, // free of a block older than the long-lived threshold
		kFlagLarge = 1u << 3,     // size at or above the "large" threshold
		kFlagReport = 1u << 4,    // part of an incident; never pruned
		kFlagAnchor = 1u << 5,    // first or last event for this pointer
	};

	enum class GameState : std::uint64_t
	{
		kInit = 0,
		kRunning = 1,
		kExiting = 2,
		kDead = 3,
	};

	enum class HealthState : std::uint32_t
	{
		kUnknown = 0,
		kGreen = 1,
		kDegraded = 2, // a tier is off or saturated; say so rather than go quiet
		kOff = 3,
	};

	// The unit of the hot ring. Exactly one cache line, so a record never
	// straddles two lines and the producer's payload write is a single
	// contiguous copy.
	struct ShmEvent
	{
		std::uint64_t seq;      // record identity within its ring (>= kFirstSeq)
		std::uint64_t tick;     // QPC ticks at capture; frequency in ShmHeader
		std::uint64_t ptr;
		std::uint64_t aux;      // kind-specific: old pointer for realloc, report id, ...
		std::uint64_t size;
		std::uint64_t site;     // caller address (return address of the hooked call)
		std::uint32_t kind;     // EventKind
		std::uint32_t threadId;
		std::uint32_t stackId;  // helper-side stack table id (0 = none)
		std::uint32_t flags;    // EventFlags
	};
	static_assert(sizeof(ShmEvent) == 64, "a record must be exactly one cache line");
	static_assert(offsetof(ShmEvent, seq) == 0);
	static_assert(offsetof(ShmEvent, kind) == 48);
	static_assert(offsetof(ShmEvent, flags) == 60);

	// One slot of a ring. `version` is a seqlock word:
	//
	//   bit 0        : 1 while a producer is writing this slot right now
	//   bits 63..1   : the record id stored here ((seq << 1) | writing)
	//   whole word 0 : the slot has never been written
	//
	// A producer invalidates the slot (odd) *before* touching the payload and
	// publishes it (even) *after*, so a consumer can never mistake a
	// half-written record for a complete one - including when the producer
	// dies mid-record, which is the case the off-game test simulates.
	struct Slot
	{
		std::uint64_t version;
		ShmEvent      event;
	};
	static_assert(sizeof(Slot) == 72);
	static_assert(offsetof(Slot, event) == 8);

	// Per-ring control block. Everything here is written by exactly one side
	// except `ownerThread`, which is the single CAS-able field that grants
	// ownership: 0 means free, any other value is the owning OS thread id
	// (Windows thread ids are never 0, so this is unambiguous). One field and
	// one compare-exchange covers both "claim a free ring" and "take over a
	// ring whose owner died without releasing it", which is why there is no
	// separate state field that could disagree with it.
	struct alignas(64) RingHeader
	{
		std::uint64_t ownerThread;    // 0 = free; otherwise the owning OS thread id
		std::uint64_t writeSeq;       // records published; producer-owned
		std::uint64_t readSeq;        // records consumed; consumer-owned
		std::uint64_t slotsOffset;    // from the mapping base
		std::uint64_t capacity;       // slots in this ring
		std::uint64_t lastActiveTick; // producer updates it periodically
		std::uint64_t claimedAtTick;  // when the ring was (re)claimed
		std::uint64_t drops;          // records the consumer had to skip in this ring
		std::uint64_t generation;     // bumped on every claim; a reset the consumer can notice
		std::uint64_t pad[7];
	};
	static_assert(sizeof(RingHeader) == 128);
	static_assert(offsetof(RingHeader, writeSeq) == 8);
	static_assert(offsetof(RingHeader, slotsOffset) == 24);

	// The session header. Deliberately padded to 512 bytes and asserted, so a
	// field added later cannot silently move the regions after it.
	struct ShmHeader
	{
		std::uint64_t magic;
		std::uint32_t layoutVersion;
		std::uint32_t headerSize;    // sizeof(ShmHeader), for a future reader
		std::uint64_t totalSize;     // the mapping size in bytes
		std::uint64_t sessionId;     // random per launch; part of the mapping name
		std::uint32_t gamePid;
		std::uint32_t hostPid;       // 0 until the helper attaches
		std::uint64_t createdAtUnix;
		std::uint64_t createdAtTick; // QPC
		std::uint64_t tickFrequency; // QPC ticks per second

		// Liveness. GetTickCount64/QPC are machine-wide, so the helper can
		// compare them with its own clock without any IPC.
		std::uint64_t heartbeatSeq;
		std::uint64_t heartbeatTick;
		std::uint64_t gameState;     // GameState

		// Ring geometry.
		std::uint64_t ringHeaderOffset;
		std::uint64_t ringCount;         // kMaxRings (the registry size)
		std::uint64_t slotCountPerRing;
		std::uint64_t slotsBytesPerRing;

		// Memcache geometry. Reserved in Phase A so that the layout does not
		// have to change when the shared ledger lands (Phase C).
		std::uint64_t memcacheOffset;
		std::uint64_t memcacheBytes;
		std::uint32_t memcacheShards;
		std::uint32_t memcacheSlotBytes;

		// Health and counters. The point of these is that silence is never
		// mistaken for safety: a degraded sentinel says so, in one place.
		std::uint32_t samplePrime;  // current sampling modulus (always a prime)
		std::uint32_t healthState;  // HealthState
		std::uint64_t eventsProduced;
		std::uint64_t eventsConsumed;
		std::uint64_t eventsDropped; // overwritten before the consumer saw them
		std::uint64_t eventsSampled;
		std::uint64_t reportsQueued;
		std::uint64_t insertFailures;
		std::uint64_t helperAttached; // 0/1
		std::uint64_t helperHeartbeat; // tick of the helper's last beat

		std::uint64_t pad[37];
	};
	static_assert(sizeof(ShmHeader) == 512);
	// The two offsets that matter most: the liveness block the helper polls, and
	// the memcache region it must find. Pinned so a field added earlier cannot
	// silently move them.
	static_assert(offsetof(ShmHeader, heartbeatSeq) == 64);
	static_assert(offsetof(ShmHeader, memcacheOffset) == 120);

	// Where each region lives inside the mapping. Computed once from the
	// configured sizes, then validated on attach.
	struct ShmLayout
	{
		std::uint64_t headerOffset = 0;
		std::uint64_t ringHeaderOffset = sizeof(ShmHeader);
		std::uint64_t slotsOffset = 0;
		std::uint64_t slotCountPerRing = 0;
		std::uint64_t slotsBytesPerRing = 0;
		std::uint64_t memcacheOffset = 0;
		std::uint64_t memcacheBytes = 0;
		std::uint64_t totalBytes = 0;

		[[nodiscard]] static ShmLayout Compute(std::uint64_t a_slotCountPerRing, std::uint64_t a_memcacheBytes) noexcept
		{
			ShmLayout layout;
			layout.slotCountPerRing = a_slotCountPerRing;
			layout.slotsBytesPerRing = a_slotCountPerRing * sizeof(Slot);
			layout.slotsOffset = layout.ringHeaderOffset + (kMaxRings * sizeof(RingHeader));
			layout.memcacheOffset = layout.slotsOffset + (kMaxRings * layout.slotsBytesPerRing);
			layout.memcacheBytes = a_memcacheBytes;
			layout.totalBytes = layout.memcacheOffset + a_memcacheBytes;
			return layout;
		}

		[[nodiscard]] std::uint64_t RingSlotsOffset(std::uint32_t a_ring) const noexcept
		{
			return slotsOffset + (static_cast<std::uint64_t>(a_ring) * slotsBytesPerRing);
		}
	};

	// ---------------------------------------------------------------------
	// Atomic access to the plain integers of the mapping.
	//
	// std::atomic_ref<const T> is not used for loads because its availability
	// varies between standard library versions; a const_cast here is local,
	// contained, and cannot be observed outside this file.
	// ---------------------------------------------------------------------

	static_assert(std::atomic_ref<std::uint64_t>::is_always_lock_free,
		"the shared layout assumes lock-free 64-bit atomics");
	static_assert(std::atomic_ref<std::uint64_t>::required_alignment <= alignof(std::uint64_t),
		"the shared layout assumes 8-byte-aligned 64-bit fields");
	static_assert(std::atomic_ref<std::uint32_t>::is_always_lock_free,
		"the shared layout assumes lock-free 32-bit atomics");

	[[nodiscard]] inline std::uint64_t LoadRelaxed(const std::uint64_t& a_value) noexcept
	{
		return std::atomic_ref<std::uint64_t>(const_cast<std::uint64_t&>(a_value)).load(std::memory_order_relaxed);
	}

	[[nodiscard]] inline std::uint64_t LoadAcquire(const std::uint64_t& a_value) noexcept
	{
		return std::atomic_ref<std::uint64_t>(const_cast<std::uint64_t&>(a_value)).load(std::memory_order_acquire);
	}

	inline void StoreRelaxed(std::uint64_t& a_value, std::uint64_t a_new) noexcept
	{
		std::atomic_ref<std::uint64_t>(a_value).store(a_new, std::memory_order_relaxed);
	}

	inline void StoreRelease(std::uint64_t& a_value, std::uint64_t a_new) noexcept
	{
		std::atomic_ref<std::uint64_t>(a_value).store(a_new, std::memory_order_release);
	}

	[[nodiscard]] inline bool CompareExchange(std::uint64_t& a_value, std::uint64_t& a_expected, std::uint64_t a_desired) noexcept
	{
		return std::atomic_ref<std::uint64_t>(a_value).compare_exchange_strong(
			a_expected, a_desired, std::memory_order_acq_rel, std::memory_order_acquire);
	}

	[[nodiscard]] inline std::uint64_t FetchAddRelaxed(std::uint64_t& a_value, std::uint64_t a_delta) noexcept
	{
		return std::atomic_ref<std::uint64_t>(a_value).fetch_add(a_delta, std::memory_order_relaxed);
	}

	[[nodiscard]] inline std::uint32_t LoadRelaxed32(const std::uint32_t& a_value) noexcept
	{
		return std::atomic_ref<std::uint32_t>(const_cast<std::uint32_t&>(a_value)).load(std::memory_order_relaxed);
	}

	inline void StoreRelaxed32(std::uint32_t& a_value, std::uint32_t a_new) noexcept
	{
		std::atomic_ref<std::uint32_t>(a_value).store(a_new, std::memory_order_relaxed);
	}

	// Seqlock word helpers. Keeping the encoding in one place means the
	// producer and the consumer cannot drift apart.
	[[nodiscard]] constexpr std::uint64_t VersionFor(std::uint64_t a_seq, bool a_writing) noexcept
	{
		return (a_seq << 1) | (a_writing ? 1u : 0u);
	}

	[[nodiscard]] constexpr std::uint64_t SeqOfVersion(std::uint64_t a_version) noexcept
	{
		return a_version >> 1;
	}

	[[nodiscard]] constexpr bool VersionIsWriting(std::uint64_t a_version) noexcept
	{
		return (a_version & 1u) != 0;
	}

	// ---------------------------------------------------------------------
	// Validation
	// ---------------------------------------------------------------------

	// Returns an empty view when the header is usable, or a human-readable
	// reason. Both sides call this immediately after mapping and refuse to
	// proceed on a non-empty result.
	[[nodiscard]] inline std::string_view Validate(const ShmHeader& a_header, const ShmLayout& a_expected, std::uint64_t a_mappedBytes) noexcept
	{
		if (a_header.magic != kShmMagic) {
			return "bad magic (the mapping is not a HeapSentinel session)";
		}
		if (a_header.layoutVersion != kShmLayoutVersion) {
			return "layout version mismatch (plugin and helper were built from different revisions)";
		}
		if (a_header.headerSize != sizeof(ShmHeader)) {
			return "header size mismatch";
		}
		if (a_header.totalSize != a_mappedBytes) {
			return "mapping size does not match the header";
		}
		if (a_header.ringHeaderOffset != a_expected.ringHeaderOffset) {
			return "ring header offset mismatch";
		}
		if (a_header.ringCount != kMaxRings) {
			return "ring count mismatch";
		}
		if (a_header.slotCountPerRing != a_expected.slotCountPerRing) {
			return "ring capacity mismatch";
		}
		if (a_header.slotsBytesPerRing != a_expected.slotsBytesPerRing) {
			return "ring size mismatch";
		}
		if (a_header.memcacheOffset != a_expected.memcacheOffset) {
			return "memcache offset mismatch";
		}
		if (a_header.memcacheBytes != a_expected.memcacheBytes) {
			return "memcache size mismatch";
		}
		return {};
	}
}

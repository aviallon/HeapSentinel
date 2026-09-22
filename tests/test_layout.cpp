#include "harness.h"

#include "Ipc/ShmLayout.h"
#include "Ipc/ShmSession.h"

#include <cstring>

using namespace hs::ipc;

namespace
{
	ShmHeader MakeValidHeader(const ShmLayout& a_layout)
	{
		ShmHeader header{};
		header.magic = kShmMagic;
		header.layoutVersion = kShmLayoutVersion;
		header.headerSize = sizeof(ShmHeader);
		header.totalSize = a_layout.totalBytes;
		header.ringHeaderOffset = a_layout.ringHeaderOffset;
		header.ringCount = kMaxRings;
		header.slotCountPerRing = a_layout.slotCountPerRing;
		header.slotsBytesPerRing = a_layout.slotsBytesPerRing;
		header.memcacheOffset = a_layout.memcacheOffset;
		header.memcacheBytes = a_layout.memcacheBytes;
		return header;
	}
}

// The static_asserts in ShmLayout.h are the real claim: they pass under MSVC and
// under GCC, which is what makes "the two processes agree on the layout" a
// checked statement rather than an assumption. Repeating the sizes here means a
// failure names the struct instead of pointing at a header line.
HS_TEST(layout_structs_have_the_expected_size)
{
	HS_CHECK_EQ(sizeof(ShmEvent), 64u);
	HS_CHECK_EQ(sizeof(Slot), 72u);
	HS_CHECK_EQ(sizeof(RingHeader), 128u);
	HS_CHECK_EQ(sizeof(ShmHeader), 512u);
}

HS_TEST(layout_regions_are_computed_consistently)
{
	const auto layout = ShmLayout::Compute(1024, 4096);
	HS_CHECK_EQ(layout.ringHeaderOffset, sizeof(ShmHeader));
	HS_CHECK_EQ(layout.slotsOffset, sizeof(ShmHeader) + kMaxRings * sizeof(RingHeader));
	HS_CHECK_EQ(layout.slotsBytesPerRing, 1024ull * 72ull);
	HS_CHECK_EQ(layout.RingSlotsOffset(0), layout.slotsOffset);
	HS_CHECK_EQ(layout.RingSlotsOffset(1), layout.slotsOffset + layout.slotsBytesPerRing);
	HS_CHECK_EQ(layout.memcacheOffset, layout.slotsOffset + kMaxRings * layout.slotsBytesPerRing);
	HS_CHECK_EQ(layout.totalBytes, layout.memcacheOffset + 4096ull);
	// The memcache region must not overlap the last ring.
	HS_CHECK(layout.memcacheOffset >= layout.RingSlotsOffset(kMaxRings - 1) + layout.slotsBytesPerRing);
}

HS_TEST(layout_validate_accepts_a_good_header)
{
	const auto layout = ShmLayout::Compute(256, 0);
	const auto header = MakeValidHeader(layout);
	HS_CHECK(Validate(header, layout, layout.totalBytes).empty());
}

HS_TEST(layout_validate_rejects_every_corruption)
{
	const auto          layout = ShmLayout::Compute(256, 0);
	const auto          good = MakeValidHeader(layout);
	const std::string_view none{};

	// A validator that accepts everything is useless, so each field is corrupted
	// in turn and the rejection is asserted. The good header is checked first in
	// layout_validate_accepts_a_good_header, so this cannot pass by rejecting
	// unconditionally.
	{
		auto header = good;
		header.magic = 0;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.layoutVersion = kShmLayoutVersion + 1;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.headerSize = sizeof(ShmHeader) - 8;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.totalSize = layout.totalBytes + 4096;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.ringHeaderOffset += 64;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.ringCount = kMaxRings - 1;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.slotCountPerRing = 128;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.slotsBytesPerRing -= 72;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.memcacheOffset += 4096;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
	{
		auto header = good;
		header.memcacheBytes = 4096;
		HS_CHECK_NE(Validate(header, layout, layout.totalBytes), none);
	}
}

HS_TEST(layout_version_word_round_trips)
{
	HS_CHECK_EQ(VersionFor(1, false), 2ull);
	HS_CHECK_EQ(VersionFor(1, true), 3ull);
	HS_CHECK_EQ(SeqOfVersion(VersionFor(12345, false)), 12345ull);
	HS_CHECK(!VersionIsWriting(VersionFor(12345, false)));
	HS_CHECK(VersionIsWriting(VersionFor(12345, true)));
	// A zero-filled slot decodes as record 0, which is exactly why record ids
	// start at 1: 0 has to keep meaning "never written".
	HS_CHECK_EQ(SeqOfVersion(0), 0ull);
	HS_CHECK_NE(SeqOfVersion(0), kFirstSeq);
}

HS_TEST(session_clock_and_name_helpers_are_sane)
{
	const std::uint64_t frequency = TickFrequency();
	HS_CHECK(frequency > 0);
	HS_CHECK(MillisecondsToTicks(1000) > 0);

	const std::uint64_t before = NowTick();
	volatile std::uint64_t sink = 0;
	for (int i = 0; i < 200000; ++i) {
		sink += static_cast<std::uint64_t>(i);
	}
	(void)sink;
	const std::uint64_t after = NowTick();
	HS_CHECK(after >= before);

	HS_CHECK_NE(NewSessionId(), 0ull);
	HS_CHECK_NE(SessionName(1, 2), SessionName(1, 3));
	HS_CHECK_NE(SessionName(1, 2), SessionName(2, 2));
}

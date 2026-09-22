#include "PCH.h"

#include "Core/Report.h"
#include "Core/BuildInfo.h"
#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/PoisonQuarantine.h"
#include "Core/ReportLog.h"
#include "Core/ShadowLedger.h"
#include "Core/Stats.h"
#include "Config.h"

#include <chrono>
#include <fstream>

namespace hs
{
	namespace
	{
		std::shared_ptr<spdlog::logger> g_reports;
		std::atomic<std::uint32_t>      g_reportsThisSecond{ 0 };
		std::atomic<std::uint64_t>      g_secondStart{ 0 };

		[[nodiscard]] bool RateLimitAllows()
		{
			const auto now = ::GetTickCount64();
			const auto start = g_secondStart.load(std::memory_order_relaxed);
			if (now - start >= 1000) {
				g_secondStart.store(now, std::memory_order_relaxed);
				g_reportsThisSecond.store(0, std::memory_order_relaxed);
			}
			return g_reportsThisSecond.fetch_add(1, std::memory_order_relaxed) < Config::Get().maxReportsPerSecond;
		}

		void WriteBmp(const std::string& a_path, std::int32_t a_width, std::int32_t a_height, const void* a_bits)
		{
			const std::uint32_t imageSize = static_cast<std::uint32_t>(a_width) * static_cast<std::uint32_t>(a_height) * 4u;
			const std::uint32_t fileSize = 14u + 40u + imageSize;

			std::ofstream out(a_path, std::ios::binary);
			if (!out) {
				return;
			}

			std::uint8_t header[54]{};
			header[0] = 'B';
			header[1] = 'M';
			std::memcpy(&header[2], &fileSize, 4);
			const std::uint32_t pixelOffset = 54;
			std::memcpy(&header[10], &pixelOffset, 4);
			const std::uint32_t dibSize = 40;
			std::memcpy(&header[14], &dibSize, 4);
			std::memcpy(&header[18], &a_width, 4);
			std::int32_t negHeight = -a_height;  // top-down
			std::memcpy(&header[22], &negHeight, 4);
			const std::uint16_t planes = 1;
			std::memcpy(&header[26], &planes, 2);
			const std::uint16_t bpp = 32;
			std::memcpy(&header[28], &bpp, 2);
			std::memcpy(&header[34], &imageSize, 4);

			out.write(reinterpret_cast<const char*>(header), sizeof(header));
			out.write(static_cast<const char*>(a_bits), imageSize);
		}
	}

	void SetupLog()
	{
		const auto dir = PluginDir();
		if (dir.empty()) {
			return;
		}

		auto logSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>((dir / "HeapSentinel.log").string(), true);
		auto log = std::make_shared<spdlog::logger>("HeapSentinel", std::move(logSink));
		log->set_level(spdlog::level::trace);
		log->flush_on(spdlog::level::trace);
		log->set_pattern("[%H:%M:%S.%e] [%l] %v");
		spdlog::set_default_logger(log);

		auto reportSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
			(dir / "HeapSentinel-reports.log").string(), static_cast<std::size_t>(kReportLogMaxBytes), kReportLogMaxFiles);
		g_reports = std::make_shared<spdlog::logger>("HeapSentinel-reports", std::move(reportSink));
		g_reports->set_level(spdlog::level::trace);
		g_reports->flush_on(spdlog::level::trace);
		g_reports->set_pattern("[%Y-%m-%d %H:%M:%S.%e] %v");

		// APPEND, never truncate: the v0.3.0 truncate flag destroyed the previous
		// run's only evidence. rotating_file_sink_mt appends and rotates at
		// kReportLogMaxBytes keeping kReportLogMaxFiles files. The header makes two
		// sessions in one file distinguishable.
		const auto now = static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
		g_reports->info("{}", BuildSessionHeader(HS_VERSION, HS_BUILD_ID, now));
	}

	void ReportSessionContext(std::string_view a_configSummary, std::uint64_t a_modlistHash, std::size_t a_moduleCount)
	{
		if (g_reports) {
			g_reports->info("{}", BuildSessionContext(a_configSummary, a_modlistHash, a_moduleCount));
		}
	}

	std::string ClassifyAddress(std::uintptr_t a_addr)
	{
		if (ModuleMap::Get().Contains(a_addr)) {
			return ModuleMap::Get().Describe(a_addr);
		}
		if (GuardedPool::Get().IsOurs(a_addr)) {
			return "guarded-pool slot";
		}
		std::uint32_t poisonIndex = 0;
		if (PoisonQuarantine::Get().DecodeFault(a_addr, poisonIndex)) {
			return "HeapSentinel poison slot " + std::to_string(poisonIndex) + " (a withheld Scaleform free)";
		}
		if (a_addr == 0xFFFFFFFFFFFFFFFFull) {
			return "0xFFFFFFFFFFFFFFFF (-1): a destroyed vtable or a bad indirect call";
		}
		if (a_addr < 0x10000ull) {
			return "null-ish pointer";
		}
		return "unmapped / unknown";
	}

	void Screenshot(std::string_view a_tag)
	{
		if (!Config::Get().reportScreenshot) {
			return;
		}

		const auto hwnd = ::GetForegroundWindow();
		if (!hwnd) {
			return;
		}

		RECT rc{};
		if (!::GetClientRect(hwnd, &rc)) {
			return;
		}
		const auto width = rc.right - rc.left;
		const auto height = rc.bottom - rc.top;
		if (width <= 0 || height <= 0) {
			return;
		}

		const auto windowDc = ::GetDC(hwnd);
		const auto memDc = ::CreateCompatibleDC(windowDc);

		BITMAPINFO info{};
		info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		info.bmiHeader.biWidth = width;
		info.bmiHeader.biHeight = -height;
		info.bmiHeader.biPlanes = 1;
		info.bmiHeader.biBitCount = 32;
		info.bmiHeader.biCompression = BI_RGB;

		void* bits = nullptr;
		const auto bitmap = ::CreateDIBSection(windowDc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
		if (bitmap && bits) {
			const auto old = ::SelectObject(memDc, bitmap);
			if (!::PrintWindow(hwnd, memDc, PW_CLIENTONLY | PW_RENDERFULLCONTENT)) {
				::BitBlt(memDc, 0, 0, width, height, windowDc, 0, 0, SRCCOPY);
			}
			::SelectObject(memDc, old);

			const auto path = (PluginDir() / (std::string("HeapSentinel-shot-") + std::string(a_tag) + ".bmp")).string();
			WriteBmp(path, width, height, bits);
			logger::info("screenshot written to {}", path);
		}

		if (bitmap) {
			::DeleteObject(bitmap);
		}
		::DeleteDC(memDc);
		::ReleaseDC(hwnd, windowDc);
	}

	void Report(std::string_view a_kind, std::string_view a_detail)
	{
		if (!RateLimitAllows()) {
			return;
		}

		logger::error("[{}] {}", a_kind, a_detail);
		if (g_reports) {
			g_reports->critical("[{}] {}", a_kind, a_detail);
		}

		// The v0.3.0 run emitted no stats at all. Emit once on the first report so
		// a short session is observable even if it never reaches the 60 s timer.
		if (ShouldEmitOnFirstReport()) {
			LogStats("first-report");
		}

		if (Config::Get().reportScreenshot) {
			Screenshot(a_kind);
		}

		if (Config::Get().reportFreeze) {
			const auto text = std::string(a_kind) + "\n\n" + std::string(a_detail) +
				"\n\nHeapSentinel is pausing so you can attach a debugger or screenshot. Close this to continue.";
			::MessageBoxA(nullptr, text.c_str(), "HeapSentinel", MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
		}
	}
}

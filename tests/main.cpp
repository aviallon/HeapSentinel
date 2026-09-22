#include "harness.h"

#include <cstring>

namespace hstest
{
	std::vector<TestCase>& Registry()
	{
		static std::vector<TestCase> registry;
		return registry;
	}

	int& CheckCount()
	{
		static int count = 0;
		return count;
	}

	int& FailureCount()
	{
		static int count = 0;
		return count;
	}

	void Fail(const char* a_file, int a_line, const std::string& a_message)
	{
		++FailureCount();
		std::fprintf(stderr, "  FAIL %s:%d: %s\n", a_file, a_line, a_message.c_str());
	}

	void Note(const std::string& a_message)
	{
		std::fprintf(stdout, "  note: %s\n", a_message.c_str());
	}

	int RunAll(const char* a_filter)
	{
		int ran = 0;
		int failedTests = 0;

		for (const auto& test : Registry()) {
			if (a_filter != nullptr && std::strstr(test.name, a_filter) == nullptr) {
				continue;
			}

			++ran;
			const int before = FailureCount();

			std::fprintf(stdout, "[ RUN  ] %s\n", test.name);
			std::fflush(stdout);
			test.fn();

			const bool ok = FailureCount() == before;
			std::fprintf(stdout, "[ %s ] %s\n", ok ? " OK " : "FAIL", test.name);
			if (!ok) {
				++failedTests;
			}
		}

		std::fprintf(stdout, "\n%d test(s) run, %d check(s), %d failure(s)\n",
			ran, CheckCount(), FailureCount());

		if (ran == 0) {
			// A filter that matches nothing must not look like success.
			std::fprintf(stderr, "no test matched the filter\n");
			return 2;
		}
		return FailureCount() == 0 ? 0 : 1;
	}
}

int main(int argc, char** argv)
{
	if (argc > 1 && std::strcmp(argv[1], "--child") == 0) {
		// The cross-process session test re-invokes this binary as the helper.
		return hstest::RunChild(argc, argv);
	}
	return hstest::RunAll(argc > 1 ? argv[1] : nullptr);
}

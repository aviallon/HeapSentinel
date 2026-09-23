#pragma once

// Minimal, dependency-free test harness.
//
// It deliberately does not use a framework: the whole point of tests/ is that it
// builds and runs on Linux and Windows with nothing but a compiler, so the ring
// protocol is verified off-game on a *second toolchain* (which is also what
// makes the layout static_asserts a cross-compiler claim rather than a claim
// about one compiler).
//
// Two rules, both learned the hard way elsewhere:
//
//  * A failure is counted, not just printed, and the process exits non-zero.
//    A check that only prints is a check that gets ignored.
//  * Every test that mutates state asserts the FINAL state, including the drop
//    and error counters. "It consumed everything" is not a check unless the
//    counters that prove nothing was silently lost are asserted too.

#include <concepts>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace hstest
{
	struct TestCase
	{
		const char* name;
		void (*fn)();
	};

	[[nodiscard]] std::vector<TestCase>& Registry();
	[[nodiscard]] int&                   CheckCount();
	[[nodiscard]] int&                   FailureCount();

	void Fail(const char* a_file, int a_line, const std::string& a_message);
	void Note(const std::string& a_message);

	// Runs every registered test (or only those whose name contains a_filter).
	// Returns the process exit code: 0 only when every check passed.
	int RunAll(const char* a_filter);

	// Child-process role for the cross-process session test. Returns the exit
	// code, or -1 when this platform has no cross-process support.
	int RunChild(int a_argc, char** a_argv);

	inline std::string ToString(bool a_value)
	{
		return a_value ? "true" : "false";
	}

	template <class T>
		requires(std::integral<T> && !std::same_as<T, bool>)
	inline std::string ToString(T a_value)
	{
		return std::to_string(a_value);
	}

	// An enum class has no implicit conversion to its underlying type, so a
	// failed HS_CHECK_EQ on one would not compile without this overload. Printing
	// the numeric value is enough for a test diagnosis.
	template <class T>
		requires(std::is_enum_v<T>)
	inline std::string ToString(T a_value)
	{
		return std::to_string(static_cast<std::underlying_type_t<T>>(a_value));
	}

	inline std::string ToString(const std::string& a_value)
	{
		return a_value;
	}

	inline std::string ToString(std::string_view a_value)
	{
		return std::string(a_value);
	}

	inline std::string ToString(const char* a_value)
	{
		return a_value == nullptr ? "(null)" : std::string(a_value);
	}

	template <class A, class B>
	void CheckEq(const char* a_file, int a_line, const A& a_actual, const B& a_expected, const char* a_actualExpr, const char* a_expectedExpr)
	{
		++CheckCount();
		if (!(a_actual == a_expected)) {
			Fail(a_file, a_line,
				std::string(a_actualExpr) + " == " + a_expectedExpr +
					" (got " + ToString(a_actual) + ", expected " + ToString(a_expected) + ")");
		}
	}

	template <class A, class B>
	void CheckNe(const char* a_file, int a_line, const A& a_actual, const B& a_unexpected, const char* a_actualExpr, const char* a_unexpectedExpr)
	{
		++CheckCount();
		if (a_actual == a_unexpected) {
			Fail(a_file, a_line,
				std::string(a_actualExpr) + " != " + a_unexpectedExpr +
					" (both are " + ToString(a_actual) + ")");
		}
	}
}

// The declaration, the registration and the definition must all name the SAME
// function. Declaring it inside the anonymous namespace while defining it at
// global scope (which is what this macro used to do) registers the address of a
// declaration that is never defined: the tests silently never run. So the
// function is declared and defined at global scope and only the registration
// lives in the anonymous namespace.
#define HS_TEST(name)                                              \
	void name();                                                   \
	namespace                                                      \
	{                                                              \
		const bool name##_registered = [] {                        \
			::hstest::Registry().push_back({ #name, &name });      \
			return true;                                           \
		}();                                                       \
	}                                                              \
	void name()

#define HS_CHECK(expr)                                             \
	do {                                                           \
		++::hstest::CheckCount();                                  \
		if (!(expr)) {                                             \
			::hstest::Fail(__FILE__, __LINE__, "expected: " #expr); \
		}                                                          \
	} while (false)

#define HS_CHECK_EQ(actual, expected) \
	::hstest::CheckEq(__FILE__, __LINE__, (actual), (expected), #actual, #expected)

#define HS_CHECK_NE(actual, unexpected) \
	::hstest::CheckNe(__FILE__, __LINE__, (actual), (unexpected), #actual, #unexpected)

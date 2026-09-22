#include "Hooks/HookTable.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hs
{
	namespace
	{
		// A deliberately tiny JSON DOM: this format is machine-generated, so the
		// parser only needs the six JSON value kinds, and treating every number
		// as a uint64 is enough (no floats appear in a committed table).
		struct JsonValue
		{
			enum class Type : std::uint8_t
			{
				kNull,
				kBool,
				kNumber,
				kString,
				kArray,
				kObject,
			};

			Type          type = Type::kNull;
			bool          boolean = false;
			std::uint64_t number = 0;
			std::string   string;
			std::vector<JsonValue> array;
			std::vector<std::pair<std::string, JsonValue>> object;

			[[nodiscard]] const JsonValue* Find(std::string_view a_key) const
			{
				for (const auto& [key, value] : object) {
					if (key == a_key) {
						return &value;
					}
				}
				return nullptr;
			}
		};

		class JsonReader
		{
		public:
			explicit JsonReader(std::string_view a_text) :
				_begin(a_text.data()), _p(a_text.data()), _end(a_text.data() + a_text.size())
			{}

			[[nodiscard]] bool Parse(JsonValue& a_out)
			{
				SkipWhitespace();
				if (!ParseValue(a_out, 0)) {
					return false;
				}
				SkipWhitespace();
				if (_p != _end) {
					return Fail("trailing content after the JSON document");
				}
				return true;
			}

			[[nodiscard]] const std::string& Error() const { return _error; }

		private:
			// Bounded so that adversarial (test) input cannot blow the stack.
			static constexpr int kMaxDepth = 64;

			[[nodiscard]] bool Fail(std::string_view a_what)
			{
				if (_error.empty()) {
					_error = std::string(a_what) + " (at byte " + std::to_string(_p - _begin) + ")";
				}
				return false;
			}

			void SkipWhitespace()
			{
				while (_p != _end && (*_p == ' ' || *_p == '\t' || *_p == '\n' || *_p == '\r')) {
					++_p;
				}
			}

			[[nodiscard]] bool Consume(char a_c)
			{
				if (_p != _end && *_p == a_c) {
					++_p;
					return true;
				}
				return false;
			}

			[[nodiscard]] bool ExpectLiteral(std::string_view a_literal)
			{
				if (static_cast<std::size_t>(_end - _p) < a_literal.size() ||
					std::string_view(_p, a_literal.size()) != a_literal) {
					return Fail("expected " + std::string(a_literal));
				}
				_p += a_literal.size();
				return true;
			}

			[[nodiscard]] bool ParseValue(JsonValue& a_out, int a_depth)
			{
				if (a_depth > kMaxDepth) {
					return Fail("nesting too deep");
				}
				SkipWhitespace();
				if (_p == _end) {
					return Fail("unexpected end of input");
				}
				switch (*_p) {
				case '{':
					return ParseObject(a_out, a_depth);
				case '[':
					return ParseArray(a_out, a_depth);
				case '"':
					a_out.type = JsonValue::Type::kString;
					return ParseString(a_out.string);
				case 't':
					a_out.type = JsonValue::Type::kBool;
					a_out.boolean = true;
					return ExpectLiteral("true");
				case 'f':
					a_out.type = JsonValue::Type::kBool;
					a_out.boolean = false;
					return ExpectLiteral("false");
				case 'n':
					a_out.type = JsonValue::Type::kNull;
					return ExpectLiteral("null");
				default:
					return ParseNumber(a_out);
				}
			}

			[[nodiscard]] bool ParseObject(JsonValue& a_out, int a_depth)
			{
				a_out.type = JsonValue::Type::kObject;
				if (!Consume('{')) {
					return Fail("expected '{'");
				}
				SkipWhitespace();
				if (Consume('}')) {
					return true;
				}
				for (;;) {
					SkipWhitespace();
					std::string key;
					if (!ParseString(key)) {
						return false;
					}
					SkipWhitespace();
					if (!Consume(':')) {
						return Fail("expected ':' after an object key");
					}
					JsonValue value;
					if (!ParseValue(value, a_depth + 1)) {
						return false;
					}
					a_out.object.emplace_back(std::move(key), std::move(value));
					SkipWhitespace();
					if (Consume(',')) {
						continue;
					}
					if (Consume('}')) {
						return true;
					}
					return Fail("expected ',' or '}' in an object");
				}
			}

			[[nodiscard]] bool ParseArray(JsonValue& a_out, int a_depth)
			{
				a_out.type = JsonValue::Type::kArray;
				if (!Consume('[')) {
					return Fail("expected '['");
				}
				SkipWhitespace();
				if (Consume(']')) {
					return true;
				}
				for (;;) {
					JsonValue value;
					if (!ParseValue(value, a_depth + 1)) {
						return false;
					}
					a_out.array.push_back(std::move(value));
					SkipWhitespace();
					if (Consume(',')) {
						continue;
					}
					if (Consume(']')) {
						return true;
					}
					return Fail("expected ',' or ']' in an array");
				}
			}

			[[nodiscard]] bool ParseString(std::string& a_out)
			{
				if (!Consume('"')) {
					return Fail("expected a string");
				}
				a_out.clear();
				while (_p != _end) {
					const auto c = static_cast<unsigned char>(*_p++);
					if (c == '"') {
						return true;
					}
					if (c < 0x20) {
						return Fail("unescaped control character in a string");
					}
					if (c != '\\') {
						a_out.push_back(static_cast<char>(c));
						continue;
					}
					if (_p == _end) {
						return Fail("truncated escape sequence");
					}
					const char esc = *_p++;
					switch (esc) {
					case '"': a_out.push_back('"'); break;
					case '\\': a_out.push_back('\\'); break;
					case '/': a_out.push_back('/'); break;
					case 'b': a_out.push_back('\b'); break;
					case 'f': a_out.push_back('\f'); break;
					case 'n': a_out.push_back('\n'); break;
					case 'r': a_out.push_back('\r'); break;
					case 't': a_out.push_back('\t'); break;
					case 'u': {
						std::uint32_t code = 0;
						if (!ParseHex4(code)) {
							return false;
						}
						AppendUtf8(a_out, code);
						break;
					}
					default:
						return Fail("unknown escape sequence");
					}
				}
				return Fail("unterminated string");
			}

			[[nodiscard]] bool ParseHex4(std::uint32_t& a_out)
			{
				if (static_cast<std::size_t>(_end - _p) < 4) {
					return Fail("truncated \\u escape");
				}
				a_out = 0;
				for (int i = 0; i < 4; ++i) {
					const char c = *_p++;
					std::uint32_t digit = 0;
					if (c >= '0' && c <= '9') {
						digit = static_cast<std::uint32_t>(c - '0');
					} else if (c >= 'a' && c <= 'f') {
						digit = static_cast<std::uint32_t>(c - 'a' + 10);
					} else if (c >= 'A' && c <= 'F') {
						digit = static_cast<std::uint32_t>(c - 'A' + 10);
					} else {
						return Fail("bad hex digit in a \\u escape");
					}
					a_out = (a_out << 4) | digit;
				}
				return true;
			}

			static void AppendUtf8(std::string& a_out, std::uint32_t a_code)
			{
				if (a_code < 0x80) {
					a_out.push_back(static_cast<char>(a_code));
				} else if (a_code < 0x800) {
					a_out.push_back(static_cast<char>(0xC0 | (a_code >> 6)));
					a_out.push_back(static_cast<char>(0x80 | (a_code & 0x3F)));
				} else {
					a_out.push_back(static_cast<char>(0xE0 | (a_code >> 12)));
					a_out.push_back(static_cast<char>(0x80 | ((a_code >> 6) & 0x3F)));
					a_out.push_back(static_cast<char>(0x80 | (a_code & 0x3F)));
				}
			}

			[[nodiscard]] bool ParseNumber(JsonValue& a_out)
			{
				a_out.type = JsonValue::Type::kNumber;
				std::uint64_t value = 0;
				bool          any = false;
				if (_p != _end && *_p == '-') {
					return Fail("negative numbers are not valid in a hook table");
				}
				while (_p != _end && *_p >= '0' && *_p <= '9') {
					const auto digit = static_cast<std::uint64_t>(*_p - '0');
					if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
						return Fail("integer overflow");
					}
					value = value * 10 + digit;
					++_p;
					any = true;
				}
				if (!any) {
					return Fail("expected a value");
				}
				if (_p != _end && (*_p == '.' || *_p == 'e' || *_p == 'E')) {
					return Fail("only integers are valid in a hook table");
				}
				a_out.number = value;
				return true;
			}

			const char* _begin;
			const char* _p;
			const char* _end;
			std::string _error;
		};

		// --- strict schema helpers -----------------------------------------

		[[nodiscard]] bool RejectUnknownKeys(const JsonValue& a_object, std::string_view a_where,
			std::initializer_list<std::string_view> a_allowed, std::string& a_error)
		{
			for (const auto& [key, _value] : a_object.object) {
				bool known = false;
				for (const auto allowed : a_allowed) {
					if (key == allowed) {
						known = true;
						break;
					}
				}
				if (!known) {
					a_error = std::string(a_where) + ": unknown key '" + key + "'";
					return false;
				}
			}
			return true;
		}

		[[nodiscard]] bool RequireObject(const JsonValue* a_value, std::string_view a_where,
			const JsonValue*& a_out, std::string& a_error)
		{
			if (a_value == nullptr || a_value->type != JsonValue::Type::kObject) {
				a_error = std::string(a_where) + ": expected an object";
				return false;
			}
			a_out = a_value;
			return true;
		}

		[[nodiscard]] bool RequireU64(const JsonValue& a_object, std::string_view a_key,
			std::string_view a_where, std::uint64_t& a_out, std::string& a_error)
		{
			const auto* value = a_object.Find(a_key);
			if (value == nullptr) {
				a_error = std::string(a_where) + ": missing key '" + std::string(a_key) + "'";
				return false;
			}
			if (value->type == JsonValue::Type::kNumber) {
				a_out = value->number;
				return true;
			}
			if (value->type == JsonValue::Type::kString) {
				// Accept "0x..." and plain decimal strings, so the format can
				// carry hex for readability without a parser change.
				const auto text = value->string;
				std::uint64_t parsed = 0;
				bool          any = false;
				std::size_t   i = 0;
				int           base = 10;
				if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
					i = 2;
					base = 16;
				}
				for (; i < text.size(); ++i) {
					const char c = text[i];
					std::uint64_t digit = 0;
					if (c >= '0' && c <= '9') {
						digit = static_cast<std::uint64_t>(c - '0');
					} else if (base == 16 && c >= 'a' && c <= 'f') {
						digit = static_cast<std::uint64_t>(c - 'a' + 10);
					} else if (base == 16 && c >= 'A' && c <= 'F') {
						digit = static_cast<std::uint64_t>(c - 'A' + 10);
					} else {
						a_error = std::string(a_where) + "." + std::string(a_key) + ": bad number";
						return false;
					}
					if (digit >= static_cast<std::uint64_t>(base)) {
						a_error = std::string(a_where) + "." + std::string(a_key) + ": bad digit";
						return false;
					}
					parsed = parsed * static_cast<std::uint64_t>(base) + digit;
					any = true;
				}
				if (!any) {
					a_error = std::string(a_where) + "." + std::string(a_key) + ": empty number";
					return false;
				}
				a_out = parsed;
				return true;
			}
			a_error = std::string(a_where) + "." + std::string(a_key) + ": expected a number";
			return false;
		}

		[[nodiscard]] bool RequireString(const JsonValue& a_object, std::string_view a_key,
			std::string_view a_where, std::string& a_out, std::string& a_error)
		{
			const auto* value = a_object.Find(a_key);
			if (value == nullptr) {
				a_error = std::string(a_where) + ": missing key '" + std::string(a_key) + "'";
				return false;
			}
			if (value->type != JsonValue::Type::kString) {
				a_error = std::string(a_where) + "." + std::string(a_key) + ": expected a string";
				return false;
			}
			a_out = value->string;
			return true;
		}

		// Optional number that may legitimately be null (a function with no
		// .pdata entry has no extent).
		[[nodiscard]] bool OptionalU64(const JsonValue& a_object, std::string_view a_key,
			std::string_view a_where, std::uint64_t& a_out, bool& a_present, std::string& a_error)
		{
			const auto* value = a_object.Find(a_key);
			if (value == nullptr) {
				a_error = std::string(a_where) + ": missing key '" + std::string(a_key) + "'";
				return false;
			}
			if (value->type == JsonValue::Type::kNull) {
				a_present = false;
				a_out = 0;
				return true;
			}
			a_present = true;
			return RequireU64(a_object, a_key, a_where, a_out, a_error);
		}

		[[nodiscard]] bool ParseRecord(const JsonValue& a_value, std::size_t a_index, HookTableRecord& a_out,
			std::string& a_error)
		{
			const auto where = "targets[" + std::to_string(a_index) + "]";
			const JsonValue* object = nullptr;
			if (!RequireObject(&a_value, where, object, a_error)) {
				return false;
			}
			if (!RejectUnknownKeys(*object, where,
					{ "target", "kind", "seId", "aeId", "name", "rva", "pdataExtent", "slotLength",
						"prologueLength", "prologueHash", "vtable" },
					a_error)) {
				return false;
			}

			std::string kind;
			if (!RequireString(*object, "target", where, a_out.target, a_error) ||
				!RequireString(*object, "kind", where, kind, a_error) ||
				!RequireString(*object, "name", where, a_out.name, a_error) ||
				!RequireU64(*object, "seId", where, a_out.seId, a_error) ||
				!RequireU64(*object, "aeId", where, a_out.aeId, a_error) ||
				!RequireU64(*object, "rva", where, a_out.rva, a_error) ||
				!OptionalU64(*object, "pdataExtent", where, a_out.pdataExtent, a_out.hasPdataExtent, a_error) ||
				!OptionalU64(*object, "slotLength", where, a_out.slotLength, a_out.hasSlotLength, a_error) ||
				!RequireU64(*object, "prologueLength", where, a_out.prologueLength, a_error) ||
				!RequireU64(*object, "prologueHash", where, a_out.prologueHash, a_error)) {
				return false;
			}

			if (kind == "rva") {
				a_out.kind = HookKind::kRva;
			} else if (kind == "vtable") {
				a_out.kind = HookKind::kVtable;
			} else {
				a_error = where + ".kind: expected 'rva' or 'vtable', got '" + kind + "'";
				return false;
			}

			const auto* vtable = object->Find("vtable");
			if (vtable != nullptr && vtable->type != JsonValue::Type::kNull) {
				const auto vtWhere = where + ".vtable";
				const JsonValue* vtObject = nullptr;
				if (!RequireObject(vtable, vtWhere, vtObject, a_error)) {
					return false;
				}
				if (!RejectUnknownKeys(*vtObject, vtWhere, { "id", "name", "rva", "slot" }, a_error)) {
					return false;
				}
				if (!RequireU64(*vtObject, "id", vtWhere, a_out.vtable.id, a_error) ||
					!RequireString(*vtObject, "name", vtWhere, a_out.vtable.name, a_error) ||
					!RequireU64(*vtObject, "rva", vtWhere, a_out.vtable.rva, a_error) ||
					!RequireU64(*vtObject, "slot", vtWhere, a_out.vtable.slot, a_error)) {
					return false;
				}
				a_out.hasVtable = true;
			}

			if (a_out.kind == HookKind::kVtable && !a_out.hasVtable) {
				a_error = where + ": a vtable target must carry a vtable block";
				return false;
			}
			if (a_out.kind == HookKind::kRva && a_out.hasVtable) {
				a_error = where + ": an rva target must not carry a vtable block";
				return false;
			}
			if (a_out.prologueLength == 0 || a_out.prologueLength > 64) {
				a_error = where + ".prologueLength: must be in [1, 64]";
				return false;
			}
			return true;
		}
	}

	const HookTableRecord* HookTable::Find(std::string_view a_target) const
	{
		for (const auto& record : records) {
			if (record.target == a_target) {
				return &record;
			}
		}
		return nullptr;
	}

	bool ParseHookTable(std::string_view a_json, HookTable& a_out, std::string& a_error)
	{
		a_out = HookTable{};
		a_error.clear();

		JsonValue root;
		JsonReader reader(a_json);
		if (!reader.Parse(root)) {
			a_error = reader.Error();
			return false;
		}
		const JsonValue* object = nullptr;
		if (!RequireObject(&root, "table", object, a_error)) {
			return false;
		}
		if (!RejectUnknownKeys(*object, "table",
				{ "schema", "generator", "identity", "addressLibrary", "names", "licensing", "hash", "targets" },
				a_error)) {
			return false;
		}
		if (!RequireString(*object, "schema", "table", a_out.schema, a_error)) {
			return false;
		}
		if (a_out.schema != "heapsentinel.hooktable/1") {
			a_error = "table.schema: unsupported schema '" + a_out.schema + "'";
			return false;
		}

		const JsonValue* identity = nullptr;
		if (!RequireObject(object->Find("identity"), "identity", identity, a_error)) {
			return false;
		}
		if (!RejectUnknownKeys(*identity, "identity",
				{ "module", "version", "size", "timeDateStamp", "sizeOfImage", "sha256" }, a_error)) {
			return false;
		}
		if (!RequireString(*identity, "module", "identity", a_out.identity.module, a_error) ||
			!RequireString(*identity, "version", "identity", a_out.identity.version, a_error) ||
			!RequireU64(*identity, "size", "identity", a_out.identity.size, a_error) ||
			!RequireU64(*identity, "timeDateStamp", "identity", a_out.identity.timeDateStamp, a_error) ||
			!RequireU64(*identity, "sizeOfImage", "identity", a_out.identity.sizeOfImage, a_error) ||
			!RequireString(*identity, "sha256", "identity", a_out.identity.sha256, a_error)) {
			return false;
		}

		const auto* targets = object->Find("targets");
		if (targets == nullptr || targets->type != JsonValue::Type::kArray) {
			a_error = "table.targets: expected an array";
			return false;
		}
		a_out.records.reserve(targets->array.size());
		for (std::size_t i = 0; i < targets->array.size(); ++i) {
			HookTableRecord record;
			if (!ParseRecord(targets->array[i], i, record, a_error)) {
				return false;
			}
			for (const auto& existing : a_out.records) {
				if (existing.target == record.target) {
					a_error = "targets[" + std::to_string(i) + "]: duplicate target '" + record.target + "'";
					return false;
				}
			}
			a_out.records.push_back(std::move(record));
		}
		if (a_out.records.empty()) {
			a_error = "table.targets: no records";
			return false;
		}
		return true;
	}
}

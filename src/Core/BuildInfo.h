#pragma once

// One place for the version and build id, so the banner, the reports-log session
// header and the CI string checks cannot drift.
//
// HS_BUILD_ID is defined by xmake.lua at configure time from `git rev-parse
// --short HEAD` (with a safe fallback when git is unavailable, e.g. a shallow
// export). It is a recognisability stamp for a run, not a security claim.

#define HS_VERSION "0.5.0"

#ifndef HS_BUILD_ID
#	define HS_BUILD_ID "unknown"
#endif
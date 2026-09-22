#pragma once

namespace hs
{
	// Installs a first-chance vectored exception handler that classifies any
	// access violation, reports it, and only ever *fixes up* faults that land
	// inside our own guarded pool. Every other fault is reported and then
	// handed to the next handler (Crash Logger SSE), so we never swallow a
	// crash we do not understand.
	void InstallVeh();
	void RemoveVeh();
}

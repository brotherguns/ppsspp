// Copyright 2013 Dolphin Emulator Project
// Licensed under GPLv2
// Refer to the license.txt file included.

#pragma once

#include <cstddef>

#include "Common/CommonTypes.h"
#include "Common/Log.h"
#include "Common/MemoryUtil.h"

#if PPSSPP_PLATFORM(SWITCH)
#include <cstdio>
#include <switch.h>
#endif // PPSSPP_PLATFORM(SWITCH)

// Everything that needs to generate code should inherit from this.
// You get memory management for free, plus, you can use all emitter functions without
// having to prefix them with gen-> or something similar.
// Example implementation:
// class JIT : public CodeBlock<ARMXEmitter>, public JitInterface {}

class CodeBlockCommon {
public:
	CodeBlockCommon() {}
	virtual ~CodeBlockCommon() {}

	bool IsInSpace(const u8 *ptr) const {
		return (ptr >= region) && (ptr < (region + region_size));
	}

	virtual const u8 *GetCodePtr() const = 0;

	u8 *GetBasePtr() const {
		return region;
	}

	size_t GetOffset(const u8 *ptr) const {
		return ptr - region;
	}

	virtual const u8 *GetCodePtrFromWritablePtr(u8 *ptr) = 0;
	virtual u8 *GetWritablePtrFromCodePtr(const u8 *ptr) = 0;

	// Highest offset ever emitted into this code space since the last clear.
	// Used to scope cache-clear work (poisoning, icache flushing) to the memory
	// that has actually been used - everything past it still holds poison from
	// the previous clear.
	size_t GetUsedCodeSpace() const {
		return highWater_;
	}

protected:
	virtual void SetCodePtr(u8 *ptr) = 0;

	// Note: this should be the readable/executable side if writable is a different pointer.
	u8 *region = nullptr;
	size_t region_size = 0;
	size_t highWater_ = 0;
};

template<class T> class CodeBlock : public CodeBlockCommon, public T {
private:
	CodeBlock(const CodeBlock &) = delete;
	void operator=(const CodeBlock &) = delete;

	// A privately used function to set the executable RAM space to something invalid.
	// For debugging usefulness it should be used to set the RAM to a host specific breakpoint instruction
	virtual void PoisonMemory(int offset) = 0;
	// Poison only [offset, end) instead of the whole space. Backends that don't override
	// this fall back to the legacy whole-space poison.
	virtual void PoisonMemoryRange(int offset, int end) {
		PoisonMemory(offset);
	}

	// True when W^X protection flips are actually required. With debugger-assisted
	// dual-mapped JIT memory (iOS 26), both mappings are permanently protected and
	// ProtectMemoryPages would be a guaranteed no-op, so skip the calls entirely.
	bool WXFlipsActive() const {
		return PlatformIsWXExclusive() && !PlatformIsDualMappedJIT();
	}

public:
	CodeBlock() {}
	~CodeBlock() {
		if (region)
			FreeCodeSpace();
	}

	// Call this before you generate any code.
	void AllocCodeSpace(int size) {
		region_size = size;
#if PPSSPP_PLATFORM(SWITCH)
		Result rc = jitCreate(&jitController, size);
		if(R_FAILED(rc)) {
			printf("Failed to create Jitbuffer of size 0x%x err: 0x%x\n", size, rc);
		}
		printf("[NXJIT]: Initialized RX: %p RW: %p\n", jitController.rx_addr, jitController.rw_addr);

		region = (u8 *)jitController.rx_addr;
		writableRegion = (u8 *)jitController.rw_addr;
#else // PPSSPP_PLATFORM(SWITCH)
#if PPSSPP_HAS_DEBUGGER_ASSISTED_JIT
		// On iOS 26 TXM devices, first try to get executable memory from an attached JIT-enabler
		// debugger (StikDebug/StikJIT etc.), aliased to a permanently writable mapping. If no
		// debugger is attached, fall back to the classic allocation (which needs JIT entitlements).
		void *writable = nullptr;
		region = (u8 *)AllocateDualMappedExecutableMemory(region_size, &writable);
		writableRegion = (u8 *)writable;
		if (region) {
			T::SetCodePointer(region, writableRegion);
			return;
		}
#endif
		// The protection will be set to RW if PlatformIsWXExclusive.
		region = (u8 *)AllocateExecutableMemory(region_size);
		writableRegion = region;
#endif // !PPSSPP_PLATFORM(SWITCH)
		T::SetCodePointer(region, writableRegion);
	}

	// Always clear code space with breakpoints, so that if someone accidentally executes
	// uninitialized, it just breaks into the debugger.
	void ClearCodeSpace(int offset) {
		if (!region) {
			return;
		}
		if (WXFlipsActive()) {
			ProtectMemoryPages(region, region_size, MEM_PROT_READ | MEM_PROT_WRITE);
		}
		// Only re-poison the space actually used since the last clear; everything past
		// the high-water mark still holds poison from before. If nothing was recorded
		// yet (very first clear, or nothing compiled since the last one), fall back to
		// poisoning everything - anonymous memory is zero-filled, and zero is not a
		// trap instruction on most architectures.
		size_t usedEnd = highWater_;
		if (usedEnd <= (size_t)offset || usedEnd > region_size) {
			usedEnd = region_size;
		}
		PoisonMemoryRange(offset, (int)usedEnd);
		highWater_ = offset;
		ResetCodePtr(offset);
		if (WXFlipsActive() && offset != 0) {
			// Need to re-protect the part we didn't clear.
			ProtectMemoryPages(region, offset, MEM_PROT_READ | MEM_PROT_EXEC);
		}
	}

	// BeginWrite/EndWrite assume that we keep appending.
	// If you don't specify a size and we later encounter an executable non-writable block, we're screwed.
	// These CANNOT be nested. We rely on the memory protection starting at READ|WRITE after start and reset.
	void BeginWrite(size_t sizeEstimate = 1) {
		_dbg_assert_msg_(!writeStart_, "Can't nest BeginWrite calls");

		// In case the last block made the current page exec/no-write, let's fix that.
		if (WXFlipsActive()) {
			writeStart_ = GetCodePtr();
			if (writeStart_ + sizeEstimate - region > (ptrdiff_t)region_size)
				sizeEstimate = region_size - (writeStart_ - region);
			writeEstimated_ = sizeEstimate;
			ProtectMemoryPages(writeStart_, sizeEstimate, MEM_PROT_READ | MEM_PROT_WRITE);
		}
	}

	// In case you now know your original estimate is wrong.
	void ContinueWrite(size_t sizeEstimate = 1) {
		_dbg_assert_msg_(writeStart_, "Must have already called BeginWrite()");
		if (WXFlipsActive()) {
			const uint8_t *pos = GetCodePtr();
			if (pos + sizeEstimate - region > (ptrdiff_t)region_size)
				sizeEstimate = region_size - (pos - region);
			writeEstimated_ = (pos - writeStart_) + sizeEstimate;
			ProtectMemoryPages(pos, sizeEstimate, MEM_PROT_READ | MEM_PROT_WRITE);
		}
	}

	void EndWrite() {
		// Track the highest offset we've emitted to, used to scope ClearCodeSpace().
		size_t used = GetCodePtr() - region;
		if (used > highWater_) {
			highWater_ = used;
		}
		// OK, we're done. Re-protect the memory we touched.
		if (WXFlipsActive() && writeStart_ != nullptr) {
			const uint8_t *end = GetCodePtr();
			size_t sz = end - writeStart_;
			if (sz > writeEstimated_)
				WARN_LOG(Log::JIT, "EndWrite(): Estimated %d bytes, wrote %d", (int)writeEstimated_, (int)sz);
			// If we protected and wrote less, we may need to unprotect.
			// Especially if we're linking blocks or similar.
			if (sz < writeEstimated_)
				sz = writeEstimated_;
			ProtectMemoryPages(writeStart_, sz, MEM_PROT_READ | MEM_PROT_EXEC);
			writeStart_ = nullptr;
		}
	}

	// Call this when shutting down. Don't rely on the destructor, even though it'll do the job.
	void FreeCodeSpace() {
#if !PPSSPP_PLATFORM(SWITCH)
		if (region && writableRegion != region) {
			// Dual-mapped allocation from debugger-assisted JIT (iOS 26). The writable side
			// is permanently writable, no need to reprotect before freeing.
			FreeDualMappedExecutableMemory(region, writableRegion, region_size);
		} else {
			ProtectMemoryPages(region, region_size, MEM_PROT_READ | MEM_PROT_WRITE);
			FreeExecutableMemory(region, region_size);
		}
#else // !PPSSPP_PLATFORM(SWITCH)
		jitClose(&jitController);
		printf("[NXJIT]: Jit closed\n");
#endif // PPSSPP_PLATFORM(SWITCH)
		region = nullptr;
		writableRegion = nullptr;
		region_size = 0;
		highWater_ = 0;
	}

	const u8 *GetCodePtr() const override {
		return T::GetCodePointer();
	}

	void ResetCodePtr(size_t offset) {
		T::SetCodePointer(region + offset, writableRegion + offset);
	}

	size_t GetSpaceLeft() const {
		return region_size - (T::GetCodePointer() - region);
	}

	const u8 *GetCodePtrFromWritablePtr(u8 *ptr) override {
		// So we can adjust region to writable space.  Might be zero.
		ptrdiff_t writable = T::GetWritableCodePtr() - T::GetCodePointer();
		return ptr - writable;
	}

	u8 *GetWritablePtrFromCodePtr(const u8 *ptr) override {
		// So we can adjust region to writable space.  Might be zero.
		ptrdiff_t writable = T::GetWritableCodePtr() - T::GetCodePointer();
		return (u8 *)ptr + writable;
	}

protected:
	void SetCodePtr(u8 *ptr) override {
		T::SetCodePointer(ptr, GetWritablePtrFromCodePtr(ptr));
	}

private:
	// Note: this is a readable pointer.
	const uint8_t *writeStart_ = nullptr;
	uint8_t *writableRegion = nullptr;
	size_t writeEstimated_ = 0;
#if PPSSPP_PLATFORM(SWITCH)
	Jit jitController;
#endif // PPSSPP_PLATFORM(SWITCH)
};

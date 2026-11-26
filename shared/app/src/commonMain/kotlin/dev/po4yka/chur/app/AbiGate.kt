package dev.po4yka.chur.app

import dev.po4yka.chur.core.model.ChurStatus

/**
 * What the native library answered to the handshake of
 * `docs/interop/FFI_CONTRACT.md` §2.
 *
 * Every field is a value the library returned. Nothing here is trusted: [gate]
 * is what decides whether the host may call further.
 */
public data class NativeHandshake(
    /** `chur_abi_version_major`. */
    val abiVersionMajor: UInt,
    /** `chur_abi_version_minor`. */
    val abiVersionMinor: UInt,
    /** `chur_capabilities`. */
    val capabilities: ULong,
    /** `chur_object_format_min`. */
    val objectFormatMin: UInt,
    /** `chur_object_format_max`. */
    val objectFormatMax: UInt,
    /** `chur_key_slot_format_min`. */
    val keySlotFormatMin: UInt,
    /** `chur_key_slot_format_max`. */
    val keySlotFormatMax: UInt,
    /** `chur_build_flavor`. */
    val buildFlavor: UInt,
)

/** The verdict of the ABI gate. */
public sealed interface GateResult {
    /** The library may be called. */
    public data class Compatible(
        /** The capabilities the host may rely on. */
        val capabilities: ULong,
    ) : GateResult

    /**
     * The library must not be called again in this process.
     *
     * `FFI_CONTRACT.md` §2 makes a major-version mismatch terminal, and
     * `ERROR_MODEL.md` maps it to [ChurStatus.ABI_INCOMPATIBLE].
     */
    public data class Incompatible(
        /** Always [ChurStatus.ABI_INCOMPATIBLE]. */
        val status: ChurStatus,
        /** A constant reason. It carries no value the library returned. */
        val reason: Reason,
    ) : GateResult

    /** Why the gate refused. */
    public enum class Reason {
        /** The major version is not the one this application was built against. */
        MAJOR_VERSION,

        /** The minor version is older than the one whose functions this application calls. */
        MINOR_VERSION,

        /** A format range is empty, so the library reads no version at all. */
        EMPTY_FORMAT_RANGE,

        /** The build declares test hooks, or is neither release nor debug. */
        BUILD_FLAVOR,
    }
}

/** The major ABI version this application was built against. */
public const val EXPECTED_ABI_MAJOR: UInt = 8u

/**
 * The oldest minor ABI version whose functions this application calls.
 *
 * `FFI_CONTRACT.md` §2 makes a minor version additive, so a newer minor is
 * accepted and an older one is refused here, before a missing symbol is
 * reached. 7.4 adds bounded pages to the locked sync inbox.
 */
public const val REQUIRED_ABI_MINOR: UInt = 4u

/** Build-flavor bit: a release build. */
public const val FLAVOR_RELEASE: UInt = 1u

/** Build-flavor bit: debug assertions are compiled in. */
public const val FLAVOR_DEBUG_ASSERTIONS: UInt = 2u

/** Build-flavor bit: test hooks are compiled in. */
public const val FLAVOR_TEST_HOOKS: UInt = 4u

/** Unreviewed wire profile for internal evaluation. */
public const val FLAVOR_INTERNAL_PQ: UInt = 8u

/**
 * Decides whether a library may be called.
 *
 * The refusals are the ones §2 and [ADR-0037] name. A panicking library
 * returns a major version of 0 and an inverted format range, so this function
 * refuses it without needing to know that a panic happened.
 *
 * @param releaseApplication whether this build of the application is a release
 * build. A release application refuses a library with debug assertions or test
 * hooks compiled in.
 *
 * [ADR-0037]: https://github.com/po4yka/Chur/blob/main/docs/adr/0037-contain-panics-in-channel-less-exports.md
 */
public fun gate(handshake: NativeHandshake, releaseApplication: Boolean): GateResult {
    if (handshake.abiVersionMajor != EXPECTED_ABI_MAJOR) {
        return refuse(GateResult.Reason.MAJOR_VERSION)
    }
    if (handshake.abiVersionMinor < REQUIRED_ABI_MINOR) {
        return refuse(GateResult.Reason.MINOR_VERSION)
    }
    if (handshake.objectFormatMin > handshake.objectFormatMax ||
        handshake.keySlotFormatMin > handshake.keySlotFormatMax
    ) {
        return refuse(GateResult.Reason.EMPTY_FORMAT_RANGE)
    }
    val release = handshake.buildFlavor and FLAVOR_RELEASE != 0u
    val debug = handshake.buildFlavor and FLAVOR_DEBUG_ASSERTIONS != 0u
    val testHooks = handshake.buildFlavor and FLAVOR_TEST_HOOKS != 0u
    if (release == debug) {
        // Both bits, or neither. Neither is the panic fallback of ADR-0037.
        return refuse(GateResult.Reason.BUILD_FLAVOR)
    }
    val internalPq = handshake.buildFlavor and FLAVOR_INTERNAL_PQ != 0u
    if (releaseApplication && (debug || testHooks || internalPq)) {
        return refuse(GateResult.Reason.BUILD_FLAVOR)
    }
    // An unknown capability bit is ignored and never enables behaviour, so the
    // mask is masked down to the eight v1 bits before the host sees it.
    return GateResult.Compatible(handshake.capabilities and V1_CAPABILITY_MASK)
}

private fun refuse(reason: GateResult.Reason): GateResult =
    GateResult.Incompatible(ChurStatus.ABI_INCOMPATIBLE, reason)

/** Bits 0 to 7, the capabilities v1 allocates. */
private const val V1_CAPABILITY_MASK: ULong = 0xffu

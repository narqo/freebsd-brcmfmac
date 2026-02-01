// Use wrapper function from C to prevent LLVM printf->puts optimization
extern fn brcmf_dbg(fmt: [*:0]const u8, ...) void;

// Chip ID register constants (from chipcommon.h)
pub const CID_ID_MASK: u32 = 0x0000ffff;
pub const CID_REV_MASK: u32 = 0x000f0000;
pub const CID_REV_SHIFT: u5 = 16;
pub const CID_TYPE_MASK: u32 = 0xf0000000;
pub const CID_TYPE_SHIFT: u5 = 28;

// Chip/SoC types
pub const SOCI_SB: u32 = 0;
pub const SOCI_AI: u32 = 1;

// SI_ENUM_BASE is the base address for chip enumeration
pub const SI_ENUM_BASE: u32 = 0x18000000;

// BAR0 window register in PCI config space
pub const BRCMF_PCIE_BAR0_WINDOW: u32 = 0x80;

// Known chip IDs
pub const BRCM_CC_4350_CHIP_ID: u32 = 0x4350;

pub const ChipInfo = extern struct {
    chip: u32,
    chiprev: u32,
    socitype: u32,
};

/// Parse chip ID register value into chip info
pub export fn brcmf_parse_chipid(regdata: u32) ChipInfo {
    return .{
        .chip = regdata & CID_ID_MASK,
        .chiprev = (regdata & CID_REV_MASK) >> CID_REV_SHIFT,
        .socitype = (regdata & CID_TYPE_MASK) >> CID_TYPE_SHIFT,
    };
}

/// Check if chip is supported
pub export fn brcmf_chip_supported(chip: u32) bool {
    return chip == BRCM_CC_4350_CHIP_ID;
}

/// Get SoC type name
pub export fn brcmf_socitype_name(socitype: u32) [*:0]const u8 {
    return switch (socitype) {
        SOCI_SB => "SB",
        SOCI_AI => "AXI",
        else => "unknown",
    };
}

// EROM (Enumeration ROM) parsing for AXI backplane

// Core IDs as extracted from EROM CI descriptors (bits[15:8])
// Note: pcie.c defines these values directly for use with brcmf_find_core
pub const BCMA_CORE_CHIPCOMMON: u32 = 0x800;
pub const BCMA_CORE_PCIE2: u32 = 0x83c;
pub const BCMA_CORE_ARM_CR4: u32 = 0x83e;
pub const BCMA_CORE_SOCRAM: u32 = 0x80e;
pub const BCMA_CORE_INTERNAL_MEM: u32 = 0x80e;

// EROM entry types (bits 1:0)
const EROM_CI: u32 = 0x01; // Component Identifier
const EROM_MP: u32 = 0x00; // Master Port
const EROM_ADDR: u32 = 0x01; // Address descriptor (bit 1 = 0, bit 0 = 1)
const EROM_END: u32 = 0x0f; // End marker

pub const CoreInfo = extern struct {
    id: u32,
    rev: u32,
    base: u32,
    wrapbase: u32,
};

/// Check if descriptor is a CI (Component Identifier) and extract core ID
/// CI format for AXI: 0x[mm][mm][cc][xx] where:
///   - bits[7:0] = 0x01 or similar (CI tag)
///   - bits[15:8] = core ID (cc)
///   - bits[31:16] = manufacturer and flags (mm)
fn parse_ci_coreid(desc: u32) ?u32 {
    // Must have CI tag bits[1:0] = 01
    if ((desc & 0x00000003) != 0x01) return null;

    // Must have upper bits indicating it's a real CI (not an address descriptor)
    // CI descriptors typically have 0x4b or 0x43 in upper byte
    const upper = (desc >> 24) & 0xff;
    if (upper != 0x4b and upper != 0x43 and upper != 0x4) return null;

    // Core ID is in bits [15:8]
    const coreid = (desc >> 8) & 0xff;

    return coreid;
}

// Address descriptor type bits (in low byte)
// From Linux bcma: bits 5:4 encode the address type
const ADDR_DESC_TYPE_MASK: u32 = 0x30;
const ADDR_DESC_TYPE_SLAVE: u32 = 0x00; // Slave port
const ADDR_DESC_TYPE_BRIDGE: u32 = 0x10; // Bridge
const ADDR_DESC_TYPE_SWRAP: u32 = 0x20; // Slave wrapper
const ADDR_DESC_TYPE_MWRAP: u32 = 0x30; // Master wrapper

/// Parse EROM address descriptor
/// Format: bit[0] = 1, bit[1] = 0 for address, bits[31:12] = address
fn parse_erom_addr(desc: u32) ?u32 {
    if ((desc & 0x03) != 0x01) return null; // Not an address descriptor
    if ((desc & 0x10) != 0) return null; // Bit 4 set = size descriptor, not address

    return desc & 0xfffff000; // 4KB aligned address
}

/// Check if address descriptor is a wrapper (master or slave)
/// Wrappers have bit 6 set (0x40) in the descriptor type field
fn is_wrap_addr(desc: u32) bool {
    if ((desc & 0x03) != 0x01) return false;
    // Wrapper addresses have 0x40 or 0x80 or 0xC0 in low byte
    // Core/slave ports have 0x00 or 0x10
    return (desc & 0x40) != 0;
}

/// Check if address descriptor is a slave wrapper
fn is_swrap_addr(desc: u32) bool {
    return is_wrap_addr(desc);
}

/// Check if address descriptor is a master wrapper
fn is_mwrap_addr(desc: u32) bool {
    return is_wrap_addr(desc);
}

/// Read callback for EROM access
pub const EromReadFn = *const fn (ctx: ?*anyopaque, offset: u32) callconv(.c) u32;

/// Find a specific core in EROM
/// Returns core info if found
///
/// AXI EROM format:
/// - CI descriptor (bits[1:0]=01): marks start of core entry
/// - Next word contains: bits[15:4] = core_id, bits[31:16] = manufacturer
/// - Following words are addresses and other info
pub export fn brcmf_find_core(
    erom_base: u32,
    read_fn: EromReadFn,
    ctx: ?*anyopaque,
    target_coreid: u32,
) CoreInfo {
    var result = CoreInfo{
        .id = 0,
        .rev = 0,
        .base = 0,
        .wrapbase = 0,
    };

    var offset: u32 = 0;
    var found_ci = false;
    var found_base = false;
    var nmw: u32 = 0;
    var ci_count: u32 = 0;

    brcmf_dbg("brcmfmac: searching EROM for core 0x%x\n", target_coreid);

    // Scan EROM entries (limit to 256 entries for safety)
    while (offset < 256 * 4) : (offset += 4) {
        const desc = read_fn(ctx, erom_base + offset);

        if (desc == 0 or desc == 0xffffffff)
            continue;

        // Check for end marker
        if ((desc & 0x0f) == EROM_END)
            break;

        // Check if this is a CI descriptor
        if (parse_ci_coreid(desc)) |coreid| {
            // Read next word for detailed core info
            const coreinfo = read_fn(ctx, erom_base + offset + 4);
            const corerev = (coreinfo >> 16) & 0xf;
            nmw = (coreinfo >> 20) & 0x1f;
            const nsw = (coreinfo >> 25) & 0x1f;

            ci_count += 1;
            brcmf_dbg("  CI[%u]: desc=0x%x info=0x%x coreid=0x%x rev=%u nmw=%u nsw=%u\n", ci_count, desc, coreinfo, coreid, corerev, nmw, nsw);

            // Reset state if we were tracking a different core
            if (found_ci and !found_base) {
                found_ci = false;
            }

            // Check if this is our target core
            if (coreid == target_coreid) {
                result.id = coreid;
                result.rev = corerev;
                found_ci = true;
                found_base = false;
                brcmf_dbg("  -> Found target! nmw+nsw=%u\n", nmw + nsw);
            }

            // Skip the coreinfo word we just read
            offset += 4;
            continue;
        }

        // Log all descriptors when tracking our target
        if (found_ci) {
            brcmf_dbg("    [0x%x]: 0x%x\n", offset, desc);
        }

        // Try parsing as address descriptor
        if (parse_erom_addr(desc)) |addr| {
            if (found_ci) {
                if (!found_base) {
                    // First address is core base
                    result.base = addr;
                    found_base = true;
                    brcmf_dbg("  -> base=0x%x\n", addr);
                } else if (result.wrapbase == 0) {
                    // Look for wrapper address - check for master or slave wrapper type
                    if (is_mwrap_addr(desc)) {
                        result.wrapbase = addr;
                        brcmf_dbg("  -> mwrap=0x%x\n", addr);
                    } else if (is_swrap_addr(desc)) {
                        result.wrapbase = addr;
                        brcmf_dbg("  -> swrap=0x%x\n", addr);
                    }
                    // Found everything we need
                    if (result.id == target_coreid and result.base != 0 and result.wrapbase != 0) {
                        return result;
                    }
                }
            }
        }
    }

    return result;
}

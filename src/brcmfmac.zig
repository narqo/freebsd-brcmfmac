// brcmfmac driver - Zig components
//
// This file contains driver logic that doesn't depend heavily on kernel headers.
// Complex kernel interactions are handled in C (main.c, pcie.c).

const printf = @extern(*const fn ([*:0]const u8, ...) callconv(.c) c_int, .{ .name = "printf" });

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

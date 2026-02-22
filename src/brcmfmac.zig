// SPDX-License-Identifier: ISC
//
// Copyright (c) 2010-2022 Broadcom Corporation
// Copyright (c) brcmfmac-freebsd contributors
//
// Based on the Linux brcmfmac driver.

extern fn brcmf_dbg(fmt: [*:0]const u8, ...) void;

pub const CID_ID_MASK: u32 = 0x0000ffff;
pub const CID_REV_MASK: u32 = 0x000f0000;
pub const CID_REV_SHIFT: u5 = 16;
pub const CID_TYPE_MASK: u32 = 0xf0000000;
pub const CID_TYPE_SHIFT: u5 = 28;

pub const SOCI_SB: u32 = 0;
pub const SOCI_AI: u32 = 1;

pub const SI_ENUM_BASE: u32 = 0x18000000;
pub const BRCMF_PCIE_BAR0_WINDOW: u32 = 0x80;

pub const BRCM_CC_4350_CHIP_ID: u32 = 0x4350;

pub const ChipInfo = extern struct {
    chip: u32,
    chiprev: u32,
    socitype: u32,
};

pub export fn brcmf_parse_chipid(regdata: u32) ChipInfo {
    return .{
        .chip = regdata & CID_ID_MASK,
        .chiprev = (regdata & CID_REV_MASK) >> CID_REV_SHIFT,
        .socitype = (regdata & CID_TYPE_MASK) >> CID_TYPE_SHIFT,
    };
}

pub export fn brcmf_chip_supported(chip: u32) bool {
    return chip == BRCM_CC_4350_CHIP_ID;
}

pub export fn brcmf_socitype_name(socitype: u32) [*:0]const u8 {
    return switch (socitype) {
        SOCI_SB => "SB",
        SOCI_AI => "AXI",
        else => "unknown",
    };
}

// DMP (Dotted Map Protocol) EROM descriptor format

const DMP_DESC_TYPE_MSK: u32 = 0x0000000f;
const DMP_DESC_EMPTY: u32 = 0x00000000;
const DMP_DESC_VALID: u32 = 0x00000001;
const DMP_DESC_COMPONENT: u32 = 0x00000001;
const DMP_DESC_MASTER_PORT: u32 = 0x00000003;
const DMP_DESC_ADDRESS: u32 = 0x00000005;
const DMP_DESC_ADDRSIZE_GT32: u32 = 0x00000008;
const DMP_DESC_EOT: u32 = 0x0000000f;

const DMP_COMP_PARTNUM: u32 = 0x000fff00;
const DMP_COMP_PARTNUM_S: u5 = 8;

const DMP_COMP_REVISION: u32 = 0xff000000;
const DMP_COMP_REVISION_S: u5 = 24;
const DMP_COMP_NUM_MWRAP: u32 = 0x0007c000;
const DMP_COMP_NUM_MWRAP_S: u5 = 14;
const DMP_COMP_NUM_SWRAP: u32 = 0x00f80000;
const DMP_COMP_NUM_SWRAP_S: u5 = 19;

const DMP_SLAVE_ADDR_BASE: u32 = 0xfffff000;
const DMP_SLAVE_TYPE: u32 = 0x000000c0;
const DMP_SLAVE_TYPE_S: u5 = 6;
const DMP_SLAVE_TYPE_SLAVE: u32 = 0;
const DMP_SLAVE_TYPE_BRIDGE: u32 = 1;
const DMP_SLAVE_TYPE_SWRAP: u32 = 2;
const DMP_SLAVE_TYPE_MWRAP: u32 = 3;
const DMP_SLAVE_SIZE_TYPE: u32 = 0x00000030;
const DMP_SLAVE_SIZE_TYPE_S: u5 = 4;
const DMP_SLAVE_SIZE_4K: u32 = 0;
const DMP_SLAVE_SIZE_8K: u32 = 1;
const DMP_SLAVE_SIZE_DESC: u32 = 3;

pub const CoreInfo = extern struct {
    id: u32,
    rev: u32,
    base: u32,
    wrapbase: u32,
};

pub const EromReadFn = *const fn (ctx: ?*anyopaque, offset: u32) callconv(.c) u32;

const EromScanner = struct {
    erom_base: u32,
    erom_addr: u32,
    read_fn: EromReadFn,
    ctx: ?*anyopaque,

    fn init(erom_base: u32, read_fn: EromReadFn, ctx: ?*anyopaque) EromScanner {
        return .{
            .erom_base = erom_base,
            .erom_addr = erom_base,
            .read_fn = read_fn,
            .ctx = ctx,
        };
    }

    fn getDesc(self: *EromScanner) u32 {
        const val = self.read_fn(self.ctx, self.erom_addr);
        self.erom_addr += 4;
        return val;
    }

    fn backup(self: *EromScanner) void {
        self.erom_addr -= 4;
    }

    fn getRegaddr(self: *EromScanner) struct { base: u32, wrap: u32 } {
        var regbase: u32 = 0;
        var wrapbase: u32 = 0;

        var val = self.getDesc();
        var desc_type = val & DMP_DESC_TYPE_MSK;

        var wraptype: u32 = undefined;
        if (desc_type == DMP_DESC_MASTER_PORT) {
            wraptype = DMP_SLAVE_TYPE_MWRAP;
        } else if ((desc_type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS) {
            self.backup();
            wraptype = DMP_SLAVE_TYPE_SWRAP;
        } else {
            self.backup();
            return .{ .base = 0, .wrap = 0 };
        }

        var safety: u32 = 0;
        while (safety < 256) : (safety += 1) {
            // find next address descriptor
            var inner_safety: u32 = 0;
            while (inner_safety < 256) : (inner_safety += 1) {
                val = self.getDesc();
                desc_type = val & DMP_DESC_TYPE_MSK;
                if (desc_type == DMP_DESC_EOT) {
                    self.backup();
                    return .{ .base = regbase, .wrap = wrapbase };
                }
                if ((desc_type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS)
                    break;
                if (desc_type == DMP_DESC_COMPONENT) {
                    self.backup();
                    return .{ .base = regbase, .wrap = wrapbase };
                }
            }

            // skip upper 32-bit address
            if ((val & DMP_DESC_ADDRSIZE_GT32) != 0)
                _ = self.getDesc();

            const sztype = (val & DMP_SLAVE_SIZE_TYPE) >> DMP_SLAVE_SIZE_TYPE_S;

            if (sztype == DMP_SLAVE_SIZE_DESC) {
                const szdesc = self.getDesc();
                if ((szdesc & DMP_DESC_ADDRSIZE_GT32) != 0)
                    _ = self.getDesc();
            }

            if (sztype != DMP_SLAVE_SIZE_4K and sztype != DMP_SLAVE_SIZE_8K)
                continue;

            const stype = (val & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S;

            if (regbase == 0 and stype == DMP_SLAVE_TYPE_SLAVE)
                regbase = val & DMP_SLAVE_ADDR_BASE;
            if (wrapbase == 0 and stype == wraptype)
                wrapbase = val & DMP_SLAVE_ADDR_BASE;

            if (regbase != 0 and wrapbase != 0)
                return .{ .base = regbase, .wrap = wrapbase };
        }

        return .{ .base = regbase, .wrap = wrapbase };
    }
};

pub export fn brcmf_find_core(
    erom_base: u32,
    read_fn: EromReadFn,
    ctx: ?*anyopaque,
    target_coreid: u32,
) CoreInfo {
    var scanner = EromScanner.init(erom_base, read_fn, ctx);
    var desc_type: u32 = 0;

    while (desc_type != DMP_DESC_EOT) {
        var val = scanner.getDesc();
        if ((val & DMP_DESC_VALID) == 0)
            continue;

        desc_type = val & DMP_DESC_TYPE_MSK;
        if (desc_type == DMP_DESC_EMPTY or desc_type == DMP_DESC_EOT)
            continue;
        if (desc_type != DMP_DESC_COMPONENT)
            continue;

        const id: u32 = (val & DMP_COMP_PARTNUM) >> DMP_COMP_PARTNUM_S;

        // second component descriptor word
        val = scanner.getDesc();
        const rev: u32 = (val & DMP_COMP_REVISION) >> DMP_COMP_REVISION_S;
        const nmw = (val & DMP_COMP_NUM_MWRAP) >> DMP_COMP_NUM_MWRAP_S;
        const nsw = (val & DMP_COMP_NUM_SWRAP) >> DMP_COMP_NUM_SWRAP_S;

        if (nmw + nsw == 0)
            continue;

        const addrs = scanner.getRegaddr();

        if (id == target_coreid) {
            return .{
                .id = id,
                .rev = rev,
                .base = addrs.base,
                .wrapbase = addrs.wrap,
            };
        }
    }

    return .{ .id = 0, .rev = 0, .base = 0, .wrapbase = 0 };
}

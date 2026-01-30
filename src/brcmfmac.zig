const c = @cImport({
    @cInclude("hack.h");
    @cInclude("sys/errno.h");
    @cInclude("sys/param.h");
    @cInclude("sys/systm.h");
    @cInclude("sys/kernel.h");
    @cInclude("sys/module.h");
});

const printf = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "printf" });

export fn brcmfmac_mod_event_handler(mod: c.module_t, cmd: c_int, arg: ?*anyopaque) c_int {
    _ = mod;
    _ = arg;

    return switch (cmd) {
        c.MOD_LOAD => {
            brcmfmac_mod_init();
            return 0;
        },
        c.MOD_UNLOAD => {
            brcmfmac_mod_exit();
            return 0;
        },
        else => c.EOPNOTSUPP,
    };
}

fn brcmfmac_mod_init() c_int {
    _ = printf("brcmfmac: kernel module init\n");
    return 0;
}

fn brcmfmac_mod_exit() c_int {
    _ = printf("brcmfmac: kernel module exit\n");
    return 0;
}

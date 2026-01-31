# Initialization Sequence

## Overview

Driver initialization proceeds through several phases:
1. PCI probe and resource mapping
2. Chip identification and reset
3. Firmware download
4. Protocol and ring setup
5. cfg80211 registration
6. Network interface creation

## PCIe probe

```c
static int brcmf_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id) {
    struct brcmf_pciedev_info *devinfo;
    struct brcmf_bus *bus;

    // Allocate device info
    devinfo = kzalloc(sizeof(*devinfo), GFP_KERNEL);
    devinfo->pdev = pdev;

    // Attach to chip (enumeration, BAR mapping)
    devinfo->ci = brcmf_chip_attach(devinfo, pdev->device, &brcmf_pcie_buscore_ops);

    // Create bus structure
    bus = kzalloc(sizeof(*bus), GFP_KERNEL);
    bus->msgbuf = kzalloc(sizeof(*bus->msgbuf), GFP_KERNEL);
    bus->dev = &pdev->dev;
    bus->bus_priv.pcie = pcie_bus_dev;
    bus->ops = &brcmf_pcie_bus_ops;
    bus->proto_type = BRCMF_PROTO_MSGBUF;
    bus->chip = devinfo->coreid;

    dev_set_drvdata(&pdev->dev, bus);

    // Get module parameters
    devinfo->settings = brcmf_get_module_param(&pdev->dev, BRCMF_BUSTYPE_PCIE,
                                               devinfo->ci->chip, devinfo->ci->chiprev);

    // Allocate driver context (wiphy)
    brcmf_alloc(&pdev->dev, devinfo->settings);

    // Request firmware
    fwreq = brcmf_pcie_prepare_fw_request(devinfo);
    brcmf_fw_get_firmwares(bus->dev, fwreq, brcmf_pcie_setup);

    return 0;
}
```

## Chip attach

```c
struct brcmf_chip *brcmf_chip_attach(void *ctx, u32 chip_id,
                                     const struct brcmf_buscore_ops *ops) {
    // Read chip ID
    regdata = ops->read32(ctx, CORE_CC_REG(SI_ENUM_BASE, chipid));
    chip->chip = regdata & CID_ID_MASK;
    chip->chiprev = (regdata & CID_REV_MASK) >> CID_REV_SHIFT;

    // Get BAR resources
    ops->prepare(ctx);

    // Enumerate cores
    brcmf_chip_recognition(ctx, ops, chip);

    // Reset chip
    ops->reset(ctx, chip);

    return chip;
}
```

## Firmware download callback

Called asynchronously when firmware files are loaded:

```c
static void brcmf_pcie_setup(struct device *dev, int ret,
                             struct brcmf_fw_request *fwreq) {
    struct brcmf_bus *bus = dev_get_drvdata(dev);
    struct brcmf_pciedev_info *devinfo = bus->bus_priv.pcie->devinfo;

    // Check firmware load result
    if (ret)
        goto fail;

    // Attach device (power management)
    brcmf_pcie_attach(devinfo);

    // Get firmware and NVRAM from request
    fw = fwreq->items[BRCMF_PCIE_FW_CODE].binary;
    nvram = fwreq->items[BRCMF_PCIE_FW_NVRAM].nv_data.data;
    nvram_len = fwreq->items[BRCMF_PCIE_FW_NVRAM].nv_data.len;
    devinfo->clm_fw = fwreq->items[BRCMF_PCIE_FW_CLM].binary;

    // Get RAM info
    brcmf_chip_get_raminfo(devinfo->ci);

    // Adjust RAM size from firmware header if present
    brcmf_pcie_adjust_ramsize(devinfo, fw->data, fw->size);

    // Download firmware and NVRAM
    brcmf_pcie_download_fw_nvram(devinfo, fw, nvram, nvram_len);

    devinfo->state = BRCMFMAC_PCIE_STATE_UP;

    // Initialize DMA rings
    brcmf_pcie_init_ringbuffers(devinfo);
    brcmf_pcie_init_scratchbuffers(devinfo);

    // Request IRQ
    brcmf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
    brcmf_pcie_request_irq(devinfo);

    // Hook rings into bus->msgbuf
    for (i = 0; i < BRCMF_NROF_COMMON_MSGRINGS; i++)
        bus->msgbuf->commonrings[i] = &devinfo->shared.commonrings[i]->commonring;

    flowrings = kcalloc(devinfo->shared.max_flowrings, sizeof(*flowrings), GFP_KERNEL);
    for (i = 0; i < devinfo->shared.max_flowrings; i++)
        flowrings[i] = &devinfo->shared.flowrings[i].commonring;
    bus->msgbuf->flowrings = flowrings;

    bus->msgbuf->rx_dataoffset = devinfo->shared.rx_dataoffset;
    bus->msgbuf->max_rxbufpost = devinfo->shared.max_rxbufpost;
    bus->msgbuf->max_flowrings = devinfo->shared.max_flowrings;

    // Continue to driver attach
    brcmf_attach(&devinfo->pdev->dev);
}
```

## Driver attach

```c
int brcmf_attach(struct device *dev) {
    struct brcmf_bus *bus_if = dev_get_drvdata(dev);
    struct brcmf_pub *drvr = bus_if->drvr;

    // Initialize interface mapping
    for (i = 0; i < ARRAY_SIZE(drvr->if2bss); i++)
        drvr->if2bss[i] = BRCMF_BSSIDX_INVALID;

    mutex_init(&drvr->proto_block);

    // Attach firmware vendor module
    brcmf_fwvid_attach(drvr);

    // Attach protocol layer
    brcmf_proto_attach(drvr);

    // Attach event handler
    brcmf_fweh_attach(drvr);

    // Register PSM watchdog handler
    brcmf_fweh_register(drvr, BRCMF_E_PSM_WATCHDOG, brcmf_psm_watchdog_notify);

    // Continue to bus started
    brcmf_bus_started(drvr, drvr->ops);

    return 0;
}
```

## Bus started

```c
static int brcmf_bus_started(struct brcmf_pub *drvr, struct cfg80211_ops *ops) {
    struct brcmf_bus *bus_if = drvr->bus_if;
    struct brcmf_if *ifp;

    // Create primary interface
    ifp = brcmf_add_if(drvr, 0, 0, false, "wlan%d", drvr->settings->mac);

    // Signal bus ready
    brcmf_bus_change_state(bus_if, BRCMF_BUS_UP);

    // Bus-specific pre-init (enable interrupts, signal host ready)
    brcmf_bus_preinit(bus_if);

    // Firmware pre-init commands
    brcmf_c_preinit_dcmds(ifp);

    // Detect features
    brcmf_feat_attach(drvr);

    // Protocol init done callback
    brcmf_proto_init_done(drvr);

    // Add interface to protocol
    brcmf_proto_add_if(drvr, ifp);

    // Attach cfg80211
    drvr->config = brcmf_cfg80211_attach(drvr, ops, drvr->settings->p2p_enable);

    // Register network interface
    brcmf_net_attach(ifp, false);

    // Register notifiers for IP address changes
    register_inetaddr_notifier(&drvr->inetaddr_notifier);
    register_inet6addr_notifier(&drvr->inet6addr_notifier);

    return 0;
}
```

## Firmware pre-init commands

```c
int brcmf_c_preinit_dcmds(struct brcmf_if *ifp) {
    struct brcmf_pub *drvr = ifp->drvr;

    // Get firmware version
    brcmf_fil_iovar_data_get(ifp, "ver", buf, sizeof(buf));

    // Get MAC address
    brcmf_fil_iovar_data_get(ifp, "cur_etheraddr", drvr->mac, sizeof(drvr->mac));
    memcpy(ifp->mac_addr, drvr->mac, ETH_ALEN);

    // Get revision info
    brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_REVINFO, &drvr->revinfo, sizeof(drvr->revinfo));

    // Set country code
    brcmf_fil_iovar_data_set(ifp, "country", &ccreq, sizeof(ccreq));

    // Set bus throttle
    brcmf_fil_iovar_int_set(ifp, "bus:txglomalign", 4);
    brcmf_fil_iovar_int_set(ifp, "ampdu_ba_wsize", 64);

    // Disable MPC (minimum power consumption) initially
    brcmf_fil_iovar_int_set(ifp, "mpc", 0);

    return 0;
}
```

## cfg80211 attach

```c
struct brcmf_cfg80211_info *brcmf_cfg80211_attach(struct brcmf_pub *drvr,
                                                  struct cfg80211_ops *ops,
                                                  bool p2pdev_forced) {
    struct brcmf_cfg80211_info *cfg;
    struct wiphy *wiphy = drvr->wiphy;
    struct brcmf_if *ifp = drvr->iflist[0];

    cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
    cfg->wiphy = wiphy;
    cfg->pub = drvr;

    // Initialize lists and mutexes
    INIT_LIST_HEAD(&cfg->vif_list);
    mutex_init(&cfg->usr_sync);
    init_waitqueue_head(&cfg->vif_event.vif_wq);
    INIT_WORK(&cfg->escan_timeout_work, brcmf_escan_timeout_worker);
    timer_setup(&cfg->escan_timeout, brcmf_escan_timeout, 0);

    // Setup wiphy bands
    brcmf_setup_wiphy(ifp);

    // Create primary VIF
    vif = brcmf_alloc_vif(cfg, NL80211_IFTYPE_STATION);
    ifp = netdev_priv(ndev);
    vif->ifp = ifp;
    vif->wdev.netdev = ndev;
    ndev->ieee80211_ptr = &vif->wdev;
    SET_NETDEV_DEV(ndev, wiphy_dev(cfg->wiphy));

    err = wl_init_priv(cfg);   // registers event handlers internally
    ifp->vif = vif;

    // Determine D11 io type and set up wiphy/bands
    brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_VERSION, &io_type);
    brcmf_setup_wiphy(wiphy, ifp);
    wiphy_register(wiphy);
    brcmf_setup_wiphybands(cfg);

    // Activate events, attach P2P/BTCOEX/PNO/TDLS
    brcmf_fweh_activate_events(ifp);
    brcmf_p2p_attach(cfg, p2pdev_forced);
    brcmf_btcoex_attach(cfg);
    brcmf_pno_attach(cfg);

    // Event activation is repeated after feature-specific registrations
    brcmf_fweh_activate_events(ifp);

    return cfg;
}
```

## Event handler registration

```c
static void brcmf_register_event_handlers(struct brcmf_cfg80211_info *cfg) {
    struct brcmf_pub *drvr = cfg->pub;

    brcmf_fweh_register(drvr, BRCMF_E_LINK, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_DEAUTH_IND, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_DEAUTH, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_DISASSOC_IND, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_ASSOC_IND, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_REASSOC_IND, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_ROAM, brcmf_notify_roaming_status);
    brcmf_fweh_register(drvr, BRCMF_E_SET_SSID, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_PSK_SUP, brcmf_notify_connect_status);
    brcmf_fweh_register(drvr, BRCMF_E_ESCAN_RESULT, brcmf_cfg80211_escan_handler);
    brcmf_fweh_register(drvr, BRCMF_E_ACTION_FRAME_RX, brcmf_p2p_notify_action_frame_rx);
    brcmf_fweh_register(drvr, BRCMF_E_P2P_DISC_LISTEN_COMPLETE,
                        brcmf_p2p_notify_listen_complete);
    brcmf_fweh_register(drvr, BRCMF_E_RSSI, brcmf_notify_rssi);
}
```

## Network interface attach

```c
int brcmf_net_attach(struct brcmf_if *ifp, bool locked) {
    struct brcmf_pub *drvr = ifp->drvr;
    struct net_device *ndev = ifp->ndev;

    // Set netdev operations
    ndev->netdev_ops = &brcmf_netdev_ops_pri;
    ndev->ethtool_ops = &brcmf_ethtool_ops;

    // Set MAC address
    eth_hw_addr_set(ndev, ifp->mac_addr);

    // Set network namespace
    dev_net_set(ndev, wiphy_net(cfg_to_wiphy(drvr->config)));

    // Initialize workers
    INIT_WORK(&ifp->multicast_work, _brcmf_set_multicast_list);
    INIT_WORK(&ifp->ndoffload_work, _brcmf_update_ndtable);

    // Register netdev
    err = register_netdev(ndev);

    netif_carrier_off(ndev);

    return 0;
}
```

## Dongle initialization

Dongle configuration is deferred to `brcmf_cfg80211_up()` via `brcmf_config_dongle()` and is not part of `brcmf_cfg80211_attach()`.

## Interface up callback

When user runs `ifconfig wlan0 up`:

```c
static int brcmf_netdev_open(struct net_device *ndev) {
    struct brcmf_if *ifp = netdev_priv(ndev);
    struct brcmf_pub *drvr = ifp->drvr;
    struct brcmf_bus *bus_if = drvr->bus_if;

    // Check bus state
    if (bus_if->state != BRCMF_BUS_UP)
        return -EAGAIN;

    atomic_set(&ifp->pend_8021x_cnt, 0);

    // Configure TOE offload
    brcmf_fil_iovar_int_get(ifp, "toe_ol", &toe_ol);
    if (toe_ol & TOE_TX_CSUM_OL)
        ndev->features |= NETIF_F_IP_CSUM;

    // Bring up cfg80211
    brcmf_cfg80211_up(ndev);

    // Carrier starts off, set when connected
    netif_carrier_off(ndev);

    return 0;
}
```

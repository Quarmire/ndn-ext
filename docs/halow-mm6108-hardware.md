# Wi-Fi HaLow / MM6108 on Orange Pi 5 Pro — hardware & firmware reference

Curated 2026-08-11. Purpose: stop guessing. This collects the vendor-documented
constraints for every layer of the stack we actually run, and maps them onto what
we have measured on the bench.

## 1. The hardware chain we run

```
Morse Micro MM6108 (802.11ah SoC)
  └─ Quectel FGH100M-H module
       └─ Seeed Wio-WM6108 Wi-Fi HaLow mini-PCIe card
            └─ WM1302 Raspberry Pi HAT (mini-PCIe carrier, SPI-wired)
                 └─ Orange Pi 5 Pro 40-pin header
                      └─ Rockchip RK3588S  spi@feb00000  (spi0.0)
```

Driver: `morse.ko` (core, bus + netdev) + `dot11ah.ko` (shim translating 802.11ah
channels/rates to 802.11ac, and S1G management frames). Release 1.16.4.

**The bus is SPI, 1-bit.** The MM6108 also supports SDIO 2.0, and the mini-PCIe
card exposes both, but the WM1302 HAT is an SPI carrier (it was designed for the
Semtech SX1302 LoRa concentrator). SDIO 4-bit is not available through this HAT —
that is a board-level constraint, not a driver one.

## 2. MM6108 host-interface facts (vendor)

* **SPI tops out around 25 Mbps at a 50 MHz clock**, and the datasheet states this
  "will be significantly reduced without DMA support" — it gives the example of an
  8-byte-per-transaction SPI interface achieving only ~2 Mbps.
* The datasheet **requires of the host**: DMA-backed SPI transactions, full-duplex
  SPI, and **level-triggered interrupts**.
* Over-the-air PHY is up to 32.5 Mbps (MM6108, 8 MHz, 256-QAM). So **the host
  interface, not the radio, is the binding constraint on this board.**
* Init quirk: the host must toggle the SPI clock ~74 times with **CS held high**
  (SD-card style), inverted from normal operation.
* `spi-max-frequency` in DT was ignored by some driver versions; `spi_clock_speed`
  module param is authoritative.

## 3. RK3588S SPI controller facts (vendor + community, same SoC as ours)

These come from a Morse Micro community thread doing exactly our experiment on an
RK3588 host, and they explain our numbers directly:

* **DMA is only used for transfers ≥ 64 bytes** (the RK3588 FIFO length). Anything
  smaller is interrupt-driven PIO. → **our 4-byte pager doorbell accesses never use
  DMA.**
* **8-byte alignment is critical.** Measured on RK3588 via spidev:
  | transfer | throughput |
  |---|---|
  | 32768 B | 21.19 Mbps |
  | 32769 B | 12.79 Mbps |
  | 65528 B | 25.17 Mbps |
  | 65535 B | 15.66 Mbps |
  "something in the chain between spi driver, dma and spi peripheral does not like
  non-8-byte-aligned transactions."
* **PM suspend/resume runs between SPI transactions** and adds latency. The
  documented workaround is the **`rockchip,always-on`** property on the SPI
  controller node.
* Max transaction 65535 B (32768 recommended); Rockchip SPI clock ceiling 50 MHz.
* Driver constants: `SPI_MAX_TRANSACTION_SIZE` 8192, `MMC_SPI_BLOCKSIZE` 512.

Their result: ~8 Mbps → **TX 15–16 Mbps, RX 10–11 Mbps** after 50 MHz clock,
8-byte alignment, PM quirks, and padding small transfers to the 64-byte DMA floor.

## 4. How this maps onto OUR measurements

Measured on o5p-2 (injection path, 900 B, 8 MHz, MCS7, ~956 f/s):

* **~95 µs fixed cost per SPI transaction, independent of size** — a 4-byte
  register read costs 85 µs where its clocking is ~0.01 µs.
  → **Explained**: sub-64-byte transfers bypass DMA (interrupt-driven PIO), plus
  per-transaction PM suspend/resume.
* **4.84 transactions per packet** (1 payload write + 3.84 small), of which the
  pager doorbells are `_morse_pager_hw_pop` 1.35/pkt and `_morse_pager_hw_put`
  1.00/pkt, both **4-byte** accesses.
* **825 µs fixed per-MPDU cost** (two independent fits: 0.827 / 0.822 ms), of which
  the driver's own counter attributes ~730–760 µs to the write path.
* Payload write: 610 µs for ~1544 B, of which ~247 µs is real clocking at 50 MHz
  and ~363 µs is overhead.

Our config vs. what the docs require:

| requirement | our state |
|---|---|
| DMA-backed SPI | `dmas`/`dma-names` present, DMA channels exist — **OK for large transfers only** |
| level-triggered IRQ | **`spi_use_edge_irq=Y`** — edge, contrary to datasheet |
| `rockchip,always-on` | **ABSENT** from `spi@feb00000` |
| 8-byte aligned transfers | **not enforced** (an earlier attempt broke probe with CMD63 — it rounded the *transaction length*, which violates the SDIO protocol; the fix must pad within a protocol-legal field) |
| 50 MHz clock | OK (`spi_clock_speed=50000000`) |

DT source: `opi5pro/nix/nixos/common/morse-micro/opi5pro-mm6108-spi.dts`.

## 5. Things already ruled out by measurement (do not re-test)

MCS, bandwidth, aggregation depth (deeper is *worse*), EDCA/backoff, TXOP,
QoS/TID, page-pool size and starvation, beacon interval, host process count,
firmware version. See `morse-throughput-instrument-traps` memory for the numbers.

Doorbell batching via SDIO fixed-address CMD53 (OP=0) **crashes the chip firmware**
— controlled A/B, do not retry.

## 6. Sources

- MM6108-MF08651-US datasheet — https://www.morsemicro.com/resources/datasheets/modules/MM6108-MF08651-US_Data_Sheet.pdf
- Quectel FGH100M-H throughput and SPI Test Mode Results (RK3588) — https://community.morsemicro.com/t/quectel-fgh100m-h-throughput-and-spi-test-mode-results/905
- FGH100M-H → WM6108 → WM1302 Pi HAT → RPi5 over SPI — https://community.morsemicro.com/t/mm6108-fgh100m-h-wm6108-wm1302-pi-hat-rpi5-over-spi/1104
- i.MX93 SPI driver for MM6108 (init quirk, clock) — https://community.morsemicro.com/t/i-mx93-spi-driver-for-mm6108/506
- SPI command set thread — https://community.morsemicro.com/t/documentation-spi-command-set-mm6108-mf08651-us/181
- morse_driver source — https://github.com/MorseMicro/morse_driver
- Seeed Wio-WM6108 wiki (schematic, Quectel spec) — https://wiki.seeedstudio.com/getting_started_with_wifi_halow_mini_pcie_module/
- RK3588S datasheet — https://rockchip.fr/RK3588S%20datasheet%20V1.7.pdf

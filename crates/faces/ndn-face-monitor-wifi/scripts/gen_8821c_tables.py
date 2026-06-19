#!/usr/bin/env python3
"""Generate `src/rtl8821c_tables.rs` from the rtw88 8821c C source.

Source of truth: lwfinger/rtw88 (`rtw8821c_table.c` for the PHY init tables,
`rtw8821c.c` for the power-on/off sequences). We copy the tables *verbatim* (the
flat phy_cond u32 arrays keep their IF/ELIF/ELSE/ENDIF branch directive words) so
the Rust side ports the same `parse_tbl_phy_cond` evaluator and selects rows by
cut/intf/rfe at runtime — exactly like the kernel. This keeps the generated data
a literal, diffable mirror of the kernel tables rather than a device-coupled
pre-flattening.

Usage:
    python3 scripts/gen_8821c_tables.py /path/to/rtw88-ref > src/rtl8821c_tables.rs
"""
import re
import sys
from pathlib import Path

# --- power-sequence macro vocabulary (main.h) -------------------------------
PWR_MACROS = {
    "RTW_PWR_CUT_TEST_MSK": 1 << 0,
    "RTW_PWR_CUT_A_MSK": 1 << 1,
    "RTW_PWR_CUT_B_MSK": 1 << 2,
    "RTW_PWR_CUT_C_MSK": 1 << 3,
    "RTW_PWR_CUT_D_MSK": 1 << 4,
    "RTW_PWR_CUT_E_MSK": 1 << 5,
    "RTW_PWR_CUT_F_MSK": 1 << 6,
    "RTW_PWR_CUT_G_MSK": 1 << 7,
    "RTW_PWR_CUT_ALL_MSK": 0xFF,
    "RTW_PWR_INTF_SDIO_MSK": 1 << 0,
    "RTW_PWR_INTF_USB_MSK": 1 << 1,
    "RTW_PWR_INTF_PCI_MSK": 1 << 2,
    "RTW_PWR_INTF_ALL_MSK": 0x0F,
    "RTW_PWR_ADDR_MAC": 0,
    "RTW_PWR_ADDR_USB": 1,
    "RTW_PWR_ADDR_PCIE": 2,
    "RTW_PWR_ADDR_SDIO": 3,
    "RTW_PWR_CMD_READ": 0,
    "RTW_PWR_CMD_WRITE": 1,
    "RTW_PWR_CMD_POLLING": 2,
    "RTW_PWR_CMD_DELAY": 3,
    "RTW_PWR_CMD_END": 4,
    "RTW_PWR_DELAY_US": 0,
    "RTW_PWR_DELAY_MS": 1,
}


def eval_expr(expr: str) -> int:
    """Evaluate a C constant expression of BIT(n) | NAMED_MSK | 0x.. | int."""
    expr = expr.strip()
    # BIT(n) -> 1<<n
    expr = re.sub(r"BIT\((\d+)\)", lambda m: str(1 << int(m.group(1))), expr)
    # named macros
    for name, val in PWR_MACROS.items():
        expr = re.sub(r"\b" + re.escape(name) + r"\b", str(val), expr)
    # grouping parens only ever wrap `|`-ORed bits — drop them
    expr = expr.replace("(", " ").replace(")", " ")
    # now expr is ints, 0x.., | and whitespace
    if not re.fullmatch(r"[0-9a-fA-FxX|\s+]*", expr):
        raise ValueError(f"unresolved token in pwr expr: {expr!r}")
    total = 0
    for tok in expr.split("|"):
        tok = tok.strip()
        if not tok:
            continue
        total |= int(tok, 0)
    return total


def slice_array(text: str, decl_re: str) -> str:
    """Return the body between the first `{` of a matching decl and its `};`."""
    m = re.search(decl_re, text)
    if not m:
        raise ValueError(f"decl not found: {decl_re}")
    start = text.index("{", m.end() - 1)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                # consume to the trailing ';'
                end = text.index(";", i)
                return text[start + 1 : i]
    raise ValueError("unterminated array")


def parse_u32_array(body: str) -> list[int]:
    return [int(t, 16) if t.lower().startswith("0x") else int(t, 0)
            for t in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", body)]


def parse_struct_rows(body: str) -> list[list[str]]:
    rows = []
    for m in re.finditer(r"\{([^{}]*)\}", body):
        fields = [f.strip() for f in m.group(1).split(",") if f.strip() != ""]
        rows.append(fields)
    return rows


def to_int(tok: str) -> int:
    tok = tok.strip()
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 0)


def emit_u32_table(name: str, vals: list[int]) -> str:
    out = [f"/// `{name}` — verbatim from rtw88 `rtw8821c_table.c` "
           f"({len(vals)} u32; phy_cond branch words retained).",
           f"pub const {name.upper()}: &[u32] = &["]
    line = "    "
    for v in vals:
        chunk = f"0x{v:08x}, "
        if len(line) + len(chunk) > 96:
            out.append(line.rstrip())
            line = "    "
        line += chunk
    if line.strip():
        out.append(line.rstrip())
    out.append("];\n")
    return "\n".join(out)


def main() -> None:
    ref = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/rtw88-ref")
    tbl = (ref / "rtw8821c_table.c").read_text()
    chip = (ref / "rtw8821c.c").read_text()

    print("//! RTL8821CU init tables, generated from lwfinger/rtw88.")
    print("//! DO NOT EDIT — regenerate with `scripts/gen_8821c_tables.py`.")
    print("//! Source: `rtw8821c_table.c` (PHY) and `rtw8821c.c` (pwrseq).")
    print("#![cfg_attr(rustfmt, rustfmt::skip)]\n")
    print("use super::pwrseq::PwrCfg;\n")

    # --- flat phy_cond u32 tables -------------------------------------------
    for name in ("rtw8821c_mac", "rtw8821c_agc", "rtw8821c_agc_btg_type2",
                 "rtw8821c_bb", "rtw8821c_rf_a"):
        body = slice_array(tbl, rf"static const u32 {name}\[\]")
        print(emit_u32_table(name, parse_u32_array(body)))

    # --- bb_pg (power-by-rate offsets) --------------------------------------
    body = slice_array(tbl, r"rtw8821c_bb_pg_type0\[\]")
    rows = parse_struct_rows(body)
    print("/// `{band, rf_path, tx_num, addr, bitmask, data}` power-by-rate offsets.")
    print("pub struct BbPg { pub band: u8, pub rf_path: u8, pub tx_num: u8, "
          "pub addr: u32, pub bitmask: u32, pub data: u32 }")
    print(f"pub const RTW8821C_BB_PG_TYPE0: &[BbPg] = &[")
    for r in rows:
        b, p, t, a, m, d = (to_int(x) for x in r[:6])
        print(f"    BbPg {{ band: {b}, rf_path: {p}, tx_num: {t}, "
              f"addr: 0x{a:08x}, bitmask: 0x{m:08x}, data: 0x{d:08x} }},")
    print("];\n")

    # --- txpwr_lmt ----------------------------------------------------------
    body = slice_array(tbl, r"rtw8821c_txpwr_lmt_type0\[\]")
    rows = parse_struct_rows(body)
    print("/// `{regd, band, bw, rs, ch, txpwr_lmt}` per-rate regulatory limit (dBm, i8).")
    print("pub struct TxPwrLmt { pub regd: u8, pub band: u8, pub bw: u8, "
          "pub rs: u8, pub ch: u8, pub lmt: i8 }")
    print(f"pub const RTW8821C_TXPWR_LMT_TYPE0: &[TxPwrLmt] = &[")
    for r in rows:
        regd, band, bw, rs, ch, lmt = r[:6]
        print(f"    TxPwrLmt {{ regd: {to_int(regd)}, band: {to_int(band)}, "
              f"bw: {to_int(bw)}, rs: {to_int(rs)}, ch: {to_int(ch)}, "
              f"lmt: {to_int(lmt)} }},")
    print("];\n")

    # --- power sequences ----------------------------------------------------
    pwr_tables = [
        "trans_carddis_to_cardemu_8821c",
        "trans_cardemu_to_act_8821c",
        "trans_act_to_cardemu_8821c",
        "trans_cardemu_to_carddis_8821c",
    ]
    for name in pwr_tables:
        body = slice_array(chip, rf"struct rtw_pwr_seq_cmd {name}\[\]")
        rows = parse_struct_rows(body)
        const = name.upper()
        print(f"/// pwrseq `{name}` from rtw88 `rtw8821c.c`.")
        print(f"pub const {const}: &[PwrCfg] = &[")
        for r in rows:
            # {offset, cut_mask, intf_mask, base, cmd, mask, value}
            offset = to_int(r[0])
            cut = eval_expr(r[1])
            intf = eval_expr(r[2])
            base = eval_expr(r[3])
            cmd = eval_expr(r[4])
            mask = eval_expr(r[5])
            value = eval_expr(r[6])
            print(f"    PwrCfg {{ offset: 0x{offset:04x}, cut_mask: 0x{cut:02x}, "
                  f"intf_mask: 0x{intf:02x}, base: {base}, cmd: {cmd}, "
                  f"mask: 0x{mask:02x}, value: 0x{value:02x} }},")
        print("];\n")

    print("/// Power-on flow (cardemu→act): the sequences applied in order at open().")
    print("pub const CARD_ENABLE_FLOW_8821C: &[&[PwrCfg]] = "
          "&[TRANS_CARDDIS_TO_CARDEMU_8821C, TRANS_CARDEMU_TO_ACT_8821C];")
    print("/// Power-off flow (act→carddis).")
    print("pub const CARD_DISABLE_FLOW_8821C: &[&[PwrCfg]] = "
          "&[TRANS_ACT_TO_CARDEMU_8821C, TRANS_CARDEMU_TO_CARDDIS_8821C];")


if __name__ == "__main__":
    main()

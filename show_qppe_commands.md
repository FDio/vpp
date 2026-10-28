# Implementing `show qppe <subsystem>` commands

Instructions for AI agents working in `src/drivers/qppe`. Follow the current
repository instructions and read the files on disk before editing: the user may
have changed them since the previous turn.

## 1. Audit the hardware definitions first

Use the local Qualcomm SDK as the register reference:

- `~/kiwi/qca-ssdk/include/hsl/hppe/`
- `~/kiwi/qca-ssdk/include/hsl/appe/`
- Corresponding accessors in `~/kiwi/qca-ssdk/src/hsl/`.
- Adapter and initialization code in `~/kiwi/qca-ssdk/src/adpt/` and `src/init/`.

The current board is APPE, which inherits many HPPE registers. Check both header
directories. A missing APPE definition may mean the HPPE layout is inherited.
Do not apply MRPPE, JHPPE, or other revision-specific conditional layouts to APPE.

Inventory all relevant configuration registers, configuration tables, status
registers, occupancy tables, and diagnostic memories. Compare the inventory with
what the driver currently prints. For every register/table, check:

- Block base address plus register/table offset.
- Entry count, stride, index origin, and physical-port/VP/queue mapping.
- Every defined field, its width, and its bit position.
- Fields split across register words.
- Reserved bits and revision-specific extensions.
- SDK access order and any read side effects.

Do not infer an absolute address from a table offset alone. Check the SDK accessor
to establish which block base is added. Use `HPPE_` or `APPE_` prefixes according
to the definition's origin, including inherited HPPE registers on APPE.

Expose all documented fields, including fields currently zero or disabled. Our
existing bitfield structures can be incomplete: bits marked reserved in the
driver may actually contain SDK-defined fields.

## 2. Organize the implementation by subsystem

`show qppe edma errors` is an explicit diagnostic command that reads clear-on-read
interrupt status and samples RX fill descriptors. Keep these status reads out of
ordinary `show qppe edma` and periodic polling. Read each status register once per
invocation and decode that saved value. Error queue IDs are meaningful only in
the context of a corresponding error indication. Descriptor samples include the
first slots and slots at the hardware consumer; compare DMA addresses only for
buffers still owned by the RX queue. Hardware may advance during a capture.

- Register the command and its formatter list in `cli.c`.
- Reuse `qppe_cli_show()` for device selection, input handling, indentation, and
  separation between formatters.
- Put decoding, formatting, display metadata, and formatting-only read helpers in
  `<subsystem>_format.c`, such as `bm_format.c`, `ac_format.c`, or `qm_format.c`.
  Keep configuration and runtime operations in `<subsystem>.c`. Shared/device
  formatting belongs in `format.c`.
- Declare externally used formatters in the corresponding `*_format.c` section of
  `qppe.h`, and register new source files in `CMakeLists.txt`.
- Put all PPE register addresses, bitfield types, field-layout macros, masks,
  encodings, and table dimensions in `ppe_hw.h`. Group each subsystem together
  below a single-line comment such as `/* VSI */`, followed by a blank line.
  EDMA register and descriptor definitions belong in `edma_hw.h` instead.
- Keep generated field-description arrays and output registries private to the
  formatter file, expanding the hardware field macros from the hardware header.
  Do not duplicate register addresses or bit positions in formatter metadata.
- Prefer bitfields in hardware structures; use named register definitions rather
  than numeric offsets embedded in formatting code.
- Arrange definitions before use; do not add forward declarations.
- Remove the relocated output from `format_qppe_dev_info()` so each subsystem's
  tables are shown by its own command.

Keep shared helpers small and concrete. Reuse code for genuinely identical
layouts, while preserving differences such as the four-bit unicast AC drop states
versus one-bit multicast/group drop states.

## 3. Print standalone configuration registers vertically

Provide `format_qppe_<subsystem>_cfg` when the subsystem has standalone
configuration registers. Always print its raw value in the heading as
`REGISTER_NAME: 0x00000001`, using `"%s: 0x%08x"`. Read the register once and
reuse that value for both the heading and field decoding. If its fields are not
known, print only the heading; do not add an `undecoded` field table.

For registers with documented fields, print each register in its own
`format_table` output: one header column containing field names, one normal
column containing values, and an unlabeled decimal column.
Add a header row labeled **Field**, **Value**, and an empty third heading.
The **Field** column must be at least 32 characters wide, expanding for longer names.

For numeric fields wider than four bits, print both hexadecimal and decimal:
`0x10` in the **Value** column and `(16)` in a separate, left-aligned column
without a heading. Use `"0x%x"` and `"(%u)"` for a `u32`. Use the field's defined hardware
width, not its current value, to make this decision. A five-bit field containing
zero must still print `0x0 (0)`. Fields of four bits or fewer use decimal only.
Read each field once and reuse the decoded value for both representations.

Example:

```text
device 'platform/3a000000.ethernet':
  BM_FB_FIFO_CFG: 0x00000010
    Field                  Value
    fb_fifo_threshold  0x10 (16)

  BM_TICK_DLY_CFG: 0x00000000
    Field      Value
    tick_delay     0
```

Use `table_add_hdr_col()` for the field-name column:

```c
table_t table = {};

table_add_hdr_col (&table, 2, "field_a", "field_b");
table_format_cell (&table, 0, 0, "0x%x", field_a);
table_format_cell (&table, 0, 1, "(%u)", field_a);
table_set_cell_align (&table, 0, 1, TTAA_LEFT);
table_format_cell (&table, 1, 0, "%u", field_b);
table_add_hdr_row (&table, 3, "Field", "Value", "");
```

In this example, `field_a` is wider than four bits and `field_b` is not.

For standalone register displays, use `format_qppe_reg_fields()` rather than
writing another field/value table formatter. This applies to EDMA and BM; apply
it to other subsystems when they have standalone registers to display. AC has no
such registers, so do not add a register display merely to use this helper.

This convention does **not** replace hardware table output. Preserve grouped
rows, two-row headers, combined columns, and alignment in AC, BM, and other table
displays. Their register-word structures do not need conversion just for this
formatting change.

For standalone register definitions, generate the bitfields and static metadata from
one `foreach_<register_type>_fields` macro. Each item is `(n_bits, field_name)`,
ordered from the least significant bits to the most significant bits. Include
reserved fields with names beginning with `_`, so their widths preserve the
positions of subsequent fields.

Represent independently defined enable bits as individual one-bit fields, such
as BM's `port_cnt_en_0` through `port_cnt_en_14`. This preserves named flag output
instead of replacing it with an unexplained bitmap.

```c
#define foreach_example_reg_t_fields \
  _ (3, priority)                    \
  _ (5, threshold)                   \
  _ (24, _reserved_8)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_example_reg_t_fields
#undef _
  };
} example_reg_t;

static const qppe_reg_field_t example_reg_fields[] = {
#define _(n_bits, name) { #name, n_bits, },
  foreach_example_reg_t_fields
#undef _
};
```

Use the shared formatter instead of repeating numeric extraction and table code:

```c
s = format (s, "%U", format_qppe_reg_fields, value,
            example_reg_fields, ARRAY_LEN (example_reg_fields));
```

Its three arguments are a `u32` register value, a
`const qppe_reg_field_t *` metadata array, and a `uword` entry count.
`ARRAY_LEN()` supplies the correct count type. The formatter skips names starting
with `_` while consuming their bit widths, prints `Field`/`Value` headings, and
applies the width-based numeric formatting rule. Callers print the register name
and manage indentation and separation between register blocks.

For dynamically generated field names, initialize the header column with
`table_add_hdr_col (&table, 1, "")`, then populate it with column index `-1`.
The current implementation does not safely support creating a header column with
zero strings.

Keep accumulated counts and live status out of these configuration-register
tables. Print them in the appropriate diagnostic table. Do not invent a config
formatter for a subsystem without standalone config registers: AC currently has
configuration tables but no separate global configuration registers.

## 4. Keep hardware tables compact without hiding information

Use one row per entry or range of entries. Combine **consecutive** entries when
all displayed fields match:

```text
vp     Q profile Q id
8-64           0    0
65             0    8
66-69          0    0
70             0   16
71-255         0    0
```

- Show a single index for a singleton and `first-last` for a range.
- Preserve nonzero exceptions and gaps. Never group nonconsecutive entries into
  a range that includes different entries.
- Include zero and disabled entries unless the hardware's documented validity
  rule makes them invalid. Zero is often a legitimate configuration.
- Compare every decoded field. Adding a printed field also requires updating
  grouping so configurations that differ in that field stay separate.
- Prefer comparing complete register words after clearing reserved bits, or
  comparing masked words, over long field-by-field conditions.
- Ignore reserved bits in grouping. Read and reconstruct all words needed for
  split fields before comparing or printing them.

Current examples include `UCAST_QUEUE_MAP_TBL`, `VSI_TBL`, BM port flow-control
configuration, and all three AC configuration tables.

## 5. Use two header rows and combined columns

Call `table_add_hdr_row()` twice before adding data. Data row numbering still
starts at zero. Both rows must describe the same number of columns.

Split long headings when useful:

```text
shared  color
ceiling aware
```

Use concise labels already established in AC output:

- `ac_en` → `en`
- `wred_en` → `wred`
- `force_ac_en` → `force_ac`

Combine related fields into one column:

```text
     resume         gap_grn_yel gap_grn_red
green/yellow/red      min/max     min/max
     36/0/0             0/0         0/0
```

- Color triplets always use **green/yellow/red**, including the values.
- Threshold-gap pairs use **min/max**, including the values.
- Use combined resume columns in group, unicast, and multicast AC configuration.
- Use combined `resume_threshold` and `drop_state` columns in the three AC
  drop-state tables.
- Center-align every slash-separated data column and both of its header cells.
  With two header rows, their row indices are `-2` and `-1`:

```c
table_set_cell_align (&table, -2, col, TTAA_CENTER);
table_set_cell_align (&table, -1, col, TTAA_CENTER);
table_set_cell_align (&table, row, col, TTAA_CENTER);
```

## 6. Headings, spacing, and decoded values

- Omit the redundant `PPE ` prefix from table/register headings.
- Use the hardware name, retaining the subsystem identity where appropriate.
- Insert one blank line before every table/register block except the first.
  This applies within a formatter as well as between formatters.
- `vlib_cli_output (vm, "")` emits nothing. Use an explicit `"\n"` for a blank
  line. Within a format string, preserve indentation with `format_newline()`.
- Put empty-state text on an indented line below its heading:

```text
IPO rules:
  none configured

Pre-IPO rules (hit 7887 miss 7741 bypass 0):
  none configured
```

Decode flags, action codes, and bypass bitmaps into meaningful names. Do not make
the user interpret an unexplained hex value. For a mostly set bypass bitmap,
`all except my_mac_check, service_code, fake_l2_proto` is clearer than listing
every bypassed operation. Omit reserved bits. Preserve unknown non-reserved
values explicitly, for example `Unknown(7)`, and investigate SDK meanings before
inventing labels.

Raw packet memory is data rather than flags and can appropriately use hex.

## 7. Reads, counters, and large memories

Show commands must read hardware without changing configuration or clearing
counters. Check read-clear behavior before adding a register to a display.
Follow SDK word ordering; some multiword tables latch data only when read from
word zero. Do not read only the final words of such a table.

Distinguish current occupancy from accumulated statistics. Occupancy belongs in
diagnostic output. Packet/byte statistics already maintained in `counters.c`
should not acquire a duplicate raw dump without a specific reason. For example,
the UNI_DROP_CNT_TBL dump was removed from `show qppe edma` because per-queue
counters cover it.

Expose large internal memories through a dedicated command rather than flooding
the ordinary subsystem output. `show qppe bm memory` prints LLM, RCM, and DM;
the DM definition alone contains 8192 entries. Retain range grouping where rows
are identical. Treat live hardware reads as a running snapshot, not an atomic
capture.

## 8. Review and report

Report missing/incorrect decoding, suspicious initialization, inherited state,
disabled profiling enables, and discrepancies with SDK defaults. Distinguish
confirmed bugs from possibilities that need board output. Do not change hardware
configuration merely to make diagnostic counters nonzero.

For example, BM physical-port settings can survive from an earlier boot until
their ports start or stop, and disabled profiling can explain zero profile
counts. A zero enable bit is meaningful information and must remain visible.

Keep edits limited to the requested subsystem and shared code genuinely needed
by the change. Follow VPP style, use C comments, and do not run
`git-clang-format` in this workflow. Do not add or run tests unless requested.
Build C changes with `ninja` from the repository root and check
`git diff --check`. Report build results and whether board verification remains.

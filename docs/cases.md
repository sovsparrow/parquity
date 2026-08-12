# Writing Cases

A Parquity **Case** describes a logical table before it becomes Parquet. It is
not a Parquet file and does not contain provider-specific objects. It contains:

- an ordered schema; and
- zero or more rows whose values follow that field order.

`check` uses the Case as its expected result:

```text
Case -> selected writer -> Parquet bytes -> selected reader -> compare with Case
```

Generic `fuzz` creates Cases. Schema-aware `fuzz` takes an empty Case as a
schema template, then generates rows under it. Saved generated reproducers use
the same `parquity.case.v1` JSON format, so their `case.json` can be passed
directly to `check`. Use `scan` instead when you already have Parquet bytes and
want to compare readers without an expected Case.

## Smallest useful example

This Case declares two fields and two rows:

```json
{
  "format": "parquity.case.v1",
  "schema": [
    {"name": "id", "nullable": false, "type": {"kind": "int64"}},
    {"name": "active", "nullable": false, "type": {"kind": "bool"}}
  ],
  "rows": [
    [101, true],
    [102, false]
  ]
}
```

Rows are arrays because the schema already supplies field names and order. In
the first row, `101` belongs to `id` and `true` belongs to `active`. In the
second, `102` belongs to `id` and `false` belongs to `active`.

Save the document as `case.json`, then run:

```console
parquity check case.json --out check-run
```

Each selected writer serializes those rows. Each selected reader reads the
result, and Parquity compares its observed schema and values with the Case. If
a path fails, Parquity may reduce the supplied Case to a smaller table that
preserves the same failure. The reproducer stores that table as `case.json` and
keeps the supplied Case as `discovered_case.json` when they differ.

## Document shape

A Case contains exactly three top-level keys: `format`, `schema`, and `rows`.
`schema` must contain at least one field. `rows` may be empty: `check` treats
that as an expected zero-row table, while `fuzz --schema` requires it for a
schema template.

`schema` is ordered. Each field has exactly `name`, `nullable`, and `type`.
Field names must be non-empty Python identifiers and unique at their struct
level. This keeps schema and value paths unambiguous without a separate field-
name escaping grammar. Field order contributes to Case identity.

Each row is an array with one value per top-level field, in schema order. A
struct value is an object containing every declared child name, including a
child whose value is `null`. Extra or missing struct keys are invalid.

Whitespace is accepted on input. Canonical output is compact UTF-8 JSON with
sorted object keys. Its SHA-256 digest is the Case identity.

The examples below put `kind` first in type objects for readability. Input
object order is not significant; canonical output sorts object keys.

## Case with tagged and nested values

Save this document as `case.json`:

```json
{
  "format": "parquity.case.v1",
  "schema": [
    {
      "name": "count",
      "nullable": false,
      "type": {"kind": "int32"}
    },
    {
      "name": "ratio",
      "nullable": false,
      "type": {"kind": "float64"}
    },
    {
      "name": "tick",
      "nullable": false,
      "type": {"kind": "timestamp", "timezone": "UTC", "unit": "ns"}
    },
    {
      "name": "amount",
      "nullable": false,
      "type": {"kind": "decimal128", "precision": 6, "scale": 2}
    },
    {
      "name": "lookup",
      "nullable": false,
      "type": {
        "kind": "map",
        "key": {"kind": "string"},
        "value": {"kind": "int64"},
        "value_nullable": true
      }
    }
  ],
  "rows": [
    [1, {"$float": "nan"}, -1, {"$decimal": "12.30"}, [["b", 2], ["a", null]]]
  ]
}
```

Run it with:

```console
parquity check case.json --out check-run
```

## Schema template for `fuzz --schema`

Schema-aware fuzz accepts an ordinary Case with no rows. The empty Case is the
schema template; Parquity does not define a second schema document format.

```json
{
  "format": "parquity.case.v1",
  "schema": [
    {
      "name": "account_id",
      "nullable": false,
      "type": {"kind": "int64"}
    },
    {
      "name": "labels",
      "nullable": true,
      "type": {
        "kind": "list",
        "item": {"kind": "string"},
        "item_nullable": false
      }
    }
  ],
  "rows": []
}
```

```console
parquity fuzz --schema schema.json --examples 100 --seed 42 \
  --max-saved 8 --out schema-run
```

The generated values preserve the supplied schema exactly. Saved reproducers
contain a canonical `case.json`, so they can be passed directly to `check`.

## Type and value reference

Every type object is one strict branch of a closed union.

| Kind | Type object | Example value |
|---|---|---|
| Boolean | `{"kind":"bool"}` | `true` |
| 32-bit integer | `{"kind":"int32"}` | `-2147483648` |
| 64-bit integer | `{"kind":"int64"}` | `9223372036854775807` |
| String | `{"kind":"string"}` | `"hello"` |
| Binary | `{"kind":"binary"}` | `{"$binary":"AAE="}` |
| 32-bit float | `{"kind":"float32"}` | `-0.0` |
| 64-bit float | `{"kind":"float64"}` | `{"$float":"inf"}` |
| Epoch day | `{"kind":"date32"}` | `0` |
| Timestamp | `{"kind":"timestamp","timezone":"UTC","unit":"us"}` | `1615705200000000` |
| Decimal | `{"kind":"decimal128","precision":8,"scale":3}` | `{"$decimal":"-12.340"}` |
| List | `{"kind":"list","item":{"kind":"int32"},"item_nullable":true}` | `[1,null,2]` |
| Fixed list | `{"kind":"fixed_list","item":{"kind":"bool"},"item_nullable":false,"size":2}` | `[true,false]` |
| Struct | `{"kind":"struct","fields":[{"name":"x","nullable":false,"type":{"kind":"int64"}}]}` | `{"x":1}` |
| Map | `{"kind":"map","key":{"kind":"string"},"value":{"kind":"int64"},"value_nullable":true}` | `[["b",2],["a",null]]` |

Top-level and struct-field nullability is declared by the field's `nullable`
boolean. List-item and map-value nullability use `item_nullable` and
`value_nullable`. Map keys are always non-null.

### Integers and temporal values

`int32` and `date32` accept signed 32-bit integers. `int64` and `timestamp`
accept signed 64-bit integers. Booleans are not integers.

`date32` values are epoch-day counts. Timestamp values are raw epoch ticks;
`unit` is one of `s`, `ms`, `us`, or `ns`. `timezone` is `null` or a non-empty,
control-free label. Case JSON does not use ISO date or datetime strings.

### Floats

Finite JSON numbers are quantized to the declared width. Finite overflow is
invalid. Non-finite values use exactly one tag key:

```json
{"$float":"nan"}
{"$float":"inf"}
{"$float":"-inf"}
```

Raw `NaN` and `Infinity` JSON tokens are rejected. Comparison uses the
declared-width bits, treats all NaNs as equal, and distinguishes `-0.0` from
`0.0`.

### Binary and decimal values

Binary values use canonical RFC 4648 Base64 with the standard alphabet and
required padding, for example `{"$binary":"AAE="}`. Whitespace, URL-safe
alphabet characters, missing padding, and other non-canonical encodings are
rejected. The empty byte string is `{"$binary":""}`.

`decimal128` precision is 1 through 38; scale is 0 through precision. Values
use a canonical fixed-scale decimal string inside `{"$decimal":"..."}`.
Exponents, a leading plus sign, redundant integer zeroes, negative zero, the
wrong fractional width, and excess coefficient precision are invalid. Decimal
values are not converted through binary floats.

### Lists, structs, and maps

`list` values have variable length. `fixed_list` values must have exactly
`size` items; `size` is an integer from 1 through 2³¹−1.

A struct type contains an ordered `fields` array. A struct value uses those
field names as exact object keys.

A map type declares `key`, `value`, and `value_nullable`. A map value is an
ordered array of `[key, value]` pairs, never a JSON object. Entry order
contributes to Case identity and replay. Keys must be unique by typed semantic
identity. Comparison matches entries by that identity and does not depend on a
provider's returned entry order.

## Generation bounds

These are fuzz bounds, not general `check` input limits:

- at most four generated rows;
- at most four top-level fields in generic fuzz;
- at most four items in a generated variable list or map;
- at most twelve characters or bytes in generated string or binary values;
- generated nesting depth at most four;
- at most 128 schema nodes and 256 expanded scalar slots per generated row.

Schema-aware fuzz accepts fixed-list widths beyond four when the complete
declared schema remains within the depth, node, and expanded-slot budgets.
Fixed lists consume their declared width in that budget.

`check` does not apply these generation bounds. It accepts any Case that passes
the grammar and value validation described above. There is no separate
Parquity row, column, or byte limit for `check`; practical size is bounded by
available memory and by the selected providers, which run in the main process.

## Rejection and current scope

Parsing rejects duplicate JSON keys, unknown keys or type parameters,
malformed tags, invalid widths or numeric ranges, nulls in non-nullable
positions, incomplete rows, and duplicate map keys before provider work.

The Case grammar does not currently represent unsigned integers, time or
duration types, unions, dictionaries, extension types, or provider-specific
metadata. This limits generated and user-authored Cases. It does not limit the
logical types that `scan` may encounter in an existing Parquet file.

## Format compatibility

`parquity.case.v1` is a durable format identity, not the Parquity package
version. Its top-level keys and type union are closed. Adding a top-level Case
field or incompatibly changing a type, value branch, canonicalization rule, or
identity rule requires a new Case format identity.

Whitespace and object-key order may vary on input. Parquity validates the
document and writes compact canonical UTF-8 JSON with sorted object keys.
Canonical bytes define the Case SHA-256 identity.

Package release policy is documented in [Versioning](../VERSIONING.md). See
[Using Parquity](usage.md) for command behavior and [Evidence and replay](evidence.md)
for saved evidence.

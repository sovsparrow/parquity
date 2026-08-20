from __future__ import annotations

import struct
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity.engines import resolve_engine
from parquity.engines.base import ProfiledEngineWriter, ProviderOperationError

TABLE = pa.table({"value": pa.array([1, 2], type=pa.int32())})


class _WriteTable(Protocol):
    def __call__(self, table: pa.Table, path: Path, **options: object) -> None: ...


class _ReadTable(Protocol):
    def __call__(self, path: Path) -> pa.Table: ...


class _ParquetModule(Protocol):
    write_table: _WriteTable
    read_table: _ReadTable


_PARQUET = cast(_ParquetModule, cast(object, pq))


def _footer_without_its_data(tmp_path: Path) -> Path:
    """Writes a Parquet file whose footer is intact and whose column data is not there.

    Truncating a file is not enough: that fails to open at all and PyArrow reports `ArrowInvalid`,
    which is an `ArrowException` and was always caught. The failure that escapes needs a readable
    footer whose offsets outrun the file.
    """
    complete = tmp_path / "complete.parquet"
    _PARQUET.write_table(pa.table({"value": pa.array(range(4096), type=pa.int32())}), complete)
    payload = complete.read_bytes()
    footer_length = struct.unpack("<I", payload[-8:-4])[0]
    body, footer = payload[: -8 - footer_length], payload[-8 - footer_length :]
    path = tmp_path / "footer-without-data.parquet"
    path.write_bytes(body[:64] + footer)
    return path


def test_a_read_failure_pyarrow_reports_as_oserror_is_owned_provider_evidence(
    tmp_path: Path,
) -> None:
    # Uncaught this escaped the adapter, and `scan` reported it as an INTERNAL_ERROR and abandoned
    # every observation already made -- so one unreadable file in a directory lost the whole run.
    path = _footer_without_its_data(tmp_path)

    with pytest.raises(OSError) as raw:
        _PARQUET.read_table(path)
    assert not isinstance(raw.value, pa.ArrowException), (
        "this file no longer produces the failure under test"
    )

    pyarrow = resolve_engine("pyarrow")
    assert pyarrow.reader is not None
    with pytest.raises(ProviderOperationError) as owned:
        pyarrow.reader.read(path)
    assert (owned.value.engine, owned.value.operation) == ("pyarrow", "read")


@pytest.mark.parametrize("profile", (None, "row-group-2"))
def test_a_write_failure_reported_as_oserror_is_owned_provider_evidence(
    profile: str | None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The write path has the same shape as the read path. A real trigger is harder to stage,
    # because Parquity writes to a directory it just created, but a full disk or a permission
    # change mid-run would arrive the same way.
    def refuse(table: pa.Table, path: Path, **options: object) -> None:
        del table, path, options
        raise OSError("controlled write failure")

    adapter = import_module("parquity.engines.pyarrow")
    monkeypatch.setattr(adapter._PARQUET, "write_table", refuse)
    pyarrow = resolve_engine("pyarrow")
    writer = pyarrow.writer
    assert isinstance(writer, ProfiledEngineWriter)
    path = tmp_path / "artifact.parquet"

    with pytest.raises(ProviderOperationError) as owned:
        if profile is None:
            writer.write(TABLE, path)
        else:
            identity = writer.writer_profile(profile)
            assert identity is not None
            writer.write_profiled(TABLE, path, identity)
    assert (owned.value.engine, owned.value.operation) == ("pyarrow", "write")

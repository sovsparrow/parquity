from __future__ import annotations

from . import records


def run_summary(
    children: tuple[records.ScanFindingRecord, ...],
    evaluated_files: int,
    failure_count: int,
    overflow_count: int,
) -> str:
    if evaluated_files == 1 and len(children) == 1 and not overflow_count:
        return file_summary(children[0], saved=True)
    base = (
        f"Parquity scanned {_count(evaluated_files, 'file')} and found "
        f"{_count(failure_count, 'distinct failure')}."
    )
    if overflow_count:
        return (
            f"{base} It stopped after saving {_count(len(children), 'file')} for reproduction; "
            f"{_count(overflow_count, 'more file')} "
            f"{'was' if overflow_count == 1 else 'were'} not scanned."
        )
    return f"{base} The affected files and diagnostics were saved."


def clean_summary(file_count: int, reader_count: int) -> str:
    target = "the file" if file_count == 1 else f"all {file_count} files"
    if reader_count == 1:
        return f"The reader read {target} successfully."
    return f"All {reader_count} readers read {target} and returned matching results."


def file_summary(record: records.ScanFindingRecord, *, saved: bool) -> str:
    outcomes = record.outcomes
    failures = tuple(
        item for item in outcomes if item.kind is not records.ReaderOutcomeKind.SUCCESS
    )
    successful = tuple(item for item in outcomes if item.kind is records.ReaderOutcomeKind.SUCCESS)
    groups = {item.observation_group for item in successful}
    total, failed, succeeded = len(outcomes), len(failures), len(successful)
    if failed == total:
        result = f"All {total} readers failed while reading the file."
    elif succeeded == 1:
        result = (
            f"{failed} of {total} readers failed while reading the file. Only one reader "
            "returned a table, so cross-reader comparison was not possible."
        )
    elif len(groups) == 1:
        result = (
            f"{failed} of {total} readers failed while reading the file. "
            f"The {succeeded} successful readers returned matching results."
        )
    elif failed:
        result = (
            f"{failed} readers failed while reading the file; the {succeeded} successful readers "
            f"returned {_count(len(groups), 'different result')}."
        )
    else:
        result = f"The readers returned {_count(len(groups), 'different result')} for the file."
    if not saved:
        return result
    if not failures:
        return f"{result} The file, diagnostics, and reader results were saved."
    return f"{result} The file and diagnostics were saved."


def _count(value: int, singular: str) -> str:
    return f"{value} {singular if value == 1 else singular + 's'}"


__all__ = ["clean_summary", "file_summary", "run_summary"]

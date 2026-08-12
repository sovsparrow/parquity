import pyarrow as pa

from parquity.scans.observations import Observation, encode_observation, group_observations
from parquity.scans.observations import ObservationDifference as Difference
from parquity.scans.observations import decode_observation as decode


def observation(engine: str, table: pa.Table) -> Observation:
    payload, metadata = encode_observation(table)
    return decode(engine, payload, metadata)


def named_value_difference(name: str) -> Difference:
    left = observation("left", pa.Table.from_arrays([pa.array([1])], names=[name]))
    right = observation("right", pa.Table.from_arrays([pa.array([2])], names=[name]))
    return group_observations((left, right)).differences[0]


__all__ = ["named_value_difference", "observation"]

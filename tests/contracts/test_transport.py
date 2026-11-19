"""JSON-lines frames."""

import pytest

from ks.contracts import (MAX_FRAME_BYTES, NoopFrame, ReplyFrame, SignReply, SignRequest, SubmitFrame, TickFrame,
                          ViewEntry, canonical, decode_frame, encode_frame, value_hash)

import samples as S


@pytest.mark.parametrize("frame", [
    TickFrame(tick=3, epoch=0, view=()), TickFrame(tick=4, epoch=None, view=()),
    TickFrame(tick=3, epoch=2, view=(ViewEntry(obj="suppliers:S-17", ver=4, hash=value_hash({"name": "Acme Steel"}),
                                               value={"name": "Acme Steel"}),)),
    NoopFrame(tick=3), SubmitFrame(tick=3, envelope=S.envelope()),
    ReplyFrame(tick=3, seq=1, record_id="r-000001", decision="exec", reason="ok", result={"ok": True},
               result_hash=S.record_exec().result_hash),
    SignRequest(header=S.envelope().header().model_copy(update={"sig": None})),
    SignReply(sig=S.envelope().sig),
])
def test_frame_roundtrip(frame):
    line = encode_frame(frame)
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert decode_frame(line) == frame


def test_frame_rejects():
    with pytest.raises(ValueError):
        decode_frame(b'{"tick":3,"type":"bogus"}\n')
    with pytest.raises(ValueError):
        decode_frame(b'{"type":"tick","tick":3}\n')  # not canonical (key order)
    with pytest.raises(canonical.CanonicalError):
        decode_frame(b" " * (MAX_FRAME_BYTES + 1))

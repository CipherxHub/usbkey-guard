import json

from usbkey_guard.journal import Journal


def test_wal_records_are_checksummed(isolated_state):
    j = Journal()
    intent = j.intent("lock", "rid1", r"C:\TestData\dummy", {"owner": "S-1-5-18"}, {})
    assert intent["crc"]
    records = j.records()
    assert records[0]["phase"] == "intent"
    assert "crc" not in records[0]
    assert len(j.unreconciled()) == 1

    j.done(intent["rid"], {"owner": "S-1-5-18"})
    assert j.unreconciled() == []


def test_torn_tail_is_ignored(isolated_state):
    j = Journal()
    intent = j.intent("lock", "rid1", r"C:\TestData\dummy", {}, {})
    j.done(intent["rid"], {})
    with open(j.records() and __import__("usbkey_guard.journal", fromlist=["WAL"]).WAL, "ab") as f:
        f.write(b'{"phase":"intent","crc":"deadbeef"')
    assert len(j.records()) == 2
    assert j.unreconciled() == []


def test_state_roundtrip(isolated_state):
    j = Journal()
    j.commit_state({"roots": [{"id": "x", "locked": True}]})
    assert j.read_state() == {"roots": [{"id": "x", "locked": True}]}


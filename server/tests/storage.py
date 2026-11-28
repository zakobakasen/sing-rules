"""Exercise the service schema using Python's stock SQLite driver."""
from pathlib import Path
import sqlite3
import unittest

SCHEMA = Path(__file__).parents[1] / "src/schema.sql"

class Storage(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(SCHEMA.read_text())

    def test_link_unassigned_then_retarget(self):
        db = self.db
        token = "a"*43
        db.execute("insert into links(owner,note,token) values (?,?,?)", ("a","subscription",token))
        lookup = "select c.output from links l join configs c on c.id=l.target and c.owner=l.owner where token=?"
        self.assertIsNone(db.execute(lookup,(token,)).fetchone())
        for note in ["first","second"]:
            row = db.execute("insert into configs(owner,note,output) values (?,?,?)", ("a",note,note))
            db.execute("update links set target=? where token=?", (row.lastrowid,token))
            self.assertEqual(db.execute(lookup,(token,)).fetchone(), (note,))

    def test_notes_and_ownership(self):
        db = self.db
        db.execute("insert into configs(owner,note) values ('a',' ')")
        for note in [" ", ""]:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("insert into configs(owner,note) values ('a',?)",(note,))
        db.execute("insert into configs(owner,note) values ('b',' ')")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("insert into links(owner,note,token,target) values ('b','link',?,1)",("X"*43,))

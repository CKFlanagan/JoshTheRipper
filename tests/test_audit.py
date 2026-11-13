import hashlib
import tempfile
import unittest
from pathlib import Path
from joshtheripper import strength, wordlist_match, verify_hash, save_report

class AuditTests(unittest.TestCase):
    def test_strength(self):
        self.assertEqual(strength('password1234')['rating'], 'weak')
        self.assertEqual(strength('Long&Unique7Phrase!')['rating'], 'strong')

    def test_wordlist(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'words.txt'
            path.write_text('example\nweakpass\n')
            self.assertTrue(wordlist_match('weakpass', path))
            self.assertFalse(wordlist_match('otherpass', path))

    def test_hash(self):
        pw = 'ExampleOnly!'
        self.assertTrue(verify_hash(pw, hashlib.sha256(pw.encode()).hexdigest(), 'sha256'))
        self.assertFalse(verify_hash('wrong', hashlib.sha256(pw.encode()).hexdigest(), 'sha256'))
        salt = b'example-salt'
        digest = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 1000).hex()
        self.assertTrue(verify_hash(pw, digest, 'pbkdf2-sha256', salt.hex(), 1000))

    def test_report_redaction(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'report.json'
            save_report({'timestamp': 'test', 'strength': strength('SecretSample!123')}, target)
            self.assertNotIn('SecretSample!123', target.read_text())

if __name__ == '__main__':
    unittest.main()

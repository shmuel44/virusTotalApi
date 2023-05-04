import unittest
import sys
import requests
import logging
from  virusTotalApi import *

class TestFileHashes(unittest.TestCase):
    def test_check_if_hash_valid(self):
        self.assertFalse(check_if_hash_valid(123)) # not a string
        self.assertFalse(check_if_hash_valid("123345")) # incorrect length
        self.assertTrue(check_if_hash_valid("84c82835a5d21bbcf75a61706d8ab549")) # valid hash

    def test_valid_fields(self):
        data = {"data": {"attributes": {"md5": "1234", "sha1": "1234", "sha256": "1234", "last_analysis_stats": {"malicious": 2}}}}
        self.assertTrue(valid_fields(data)) # valid fields
        data = {"data": {"attributes": {"md5": "1234", "sha1": "1234", "sha256": "1234"}}}
        self.assertFalse(valid_fields(data)) # last_analysis_stats missing
        data = {"data": {"attributes": {"md5": "1234", "sha1": "1234", "sha256": "1234", "last_analysis_stats": {"malicious123": 2}}}}
        self.assertFalse(valid_fields(data)) # malicious missing in last_analysis_stats
        
  
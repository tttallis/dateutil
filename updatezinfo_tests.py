from updatezinfo import main

import unittest


class UpdateZInfoTester(unittest.TestCase):
    def _run_script(self, *args, **kwargs):
        """ Run the script with the specified ``args`` """
        main(*args, **kwargs)

    def testBasic(self):
        """ Test that the basic run doesn't actually throw an error """
        self._run_script()

    def testMetadata(self):
        self._run_script()

    def testZoneInfo(self):
        """ Test that it can take a zoneinfo file as input """
        pass

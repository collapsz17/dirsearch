#!/usr/bin/env python3

import unittest
from unittest.mock import patch

from lib.view.terminal import CLI


class TestTerminalCLI(unittest.TestCase):
    @patch("sys.stdout.isatty", return_value=False)
    def test_last_path_is_suppressed_without_tty(self, _mock_isatty):
        cli = CLI()

        with patch.object(cli, "in_line") as mock_in_line:
            cli.last_path(1, 10, 1, 1, 1, 0)

        mock_in_line.assert_not_called()


if __name__ == "__main__":
    unittest.main()

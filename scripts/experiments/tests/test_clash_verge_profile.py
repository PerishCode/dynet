from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import clash_verge_profile as cvp


class ClashVergeProfileTest(unittest.TestCase):
    def test_go_nanotime(self) -> None:
        parsed = cvp.parse_time("2026-05-22T10:40:49.847154123+08:00")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.microsecond, 847154)
        self.assertEqual(cvp.time_bucket(parsed, 60), "2026-05-22T10:00+0800")
        self.assertEqual(cvp.time_bucket(parsed, 5), "2026-05-22T10:40+0800")

    def test_time_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            service = root / "service"
            service.mkdir()
            (service / "service.log").write_text(
                "\n".join(
                    [
                        '[x] time="2026-05-22T10:40:49.847154123+08:00" level=info '
                        'msg="[TCP] 127.0.0.1:5000 --> api.github.com:443 '
                        'match RuleSet(github) using GitHub[a]"',
                        '[x] time="2026-05-22T10:42:01.000000999+08:00" level=warning '
                        'msg="[TCP] dial GitHub[a] (match RuleSet(github)) '
                        '127.0.0.1:5001 --> api.github.com:443 error: context deadline exceeded"',
                    ]
                )
                + "\n"
            )

            events, errors, lines = cvp.parse_logs(cvp.iter_log_files(root))
            report = cvp.build_report(root, cvp.iter_log_files(root), events, errors, lines)

        self.assertEqual(report["summary"]["events"], 1)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["distribution"]["byHour"], [{"key": "2026-05-22T10:00+0800", "count": 1}])
        self.assertEqual(
            report["distribution"]["byFiveMinute"],
            [{"key": "2026-05-22T10:40+0800", "count": 1}],
        )
        self.assertEqual(report["errors"]["byReason"], [{"key": "timeout", "count": 1}])
        self.assertEqual(report["topDomains"][0]["activeWindows5m"], 1)


if __name__ == "__main__":
    unittest.main()

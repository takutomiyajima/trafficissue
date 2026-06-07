import csv
import tempfile
import unittest
from pathlib import Path

from normalize_pcap_metadata import normalize_file


class NormalizePcapMetadataTest(unittest.TestCase):
    def test_normalize_file_accepts_common_pcapdroid_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            raw_path = base / "raw.csv"
            output_path = base / "pcap_metadata.csv"
            raw_path.write_text(
                "Time,App,Host,Remote IP,Remote Port,L4 Proto,Sent Bytes,Received Bytes\n"
                "2026-06-07T00:00:01Z,com.example,api.example.com,203.0.113.10,443,TCP,120,500\n",
                encoding="utf-8",
            )

            count = normalize_file(str(raw_path), str(output_path), source="pcapdroid")

            self.assertEqual(count, 1)
            with open(output_path, newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["timestamp"], "1780790401")
            self.assertEqual(row["package"], "com.example")
            self.assertEqual(row["destination_host"], "api.example.com")
            self.assertEqual(row["destination_ip"], "203.0.113.10")
            self.assertEqual(row["destination_port"], "443")
            self.assertEqual(row["protocol"], "TCP")
            self.assertEqual(row["source"], "pcapdroid")


if __name__ == "__main__":
    unittest.main()

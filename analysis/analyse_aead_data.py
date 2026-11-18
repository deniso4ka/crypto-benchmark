import csv
import statistics
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
files = {
    "Lenovo": BASE_DIR / "results" / "run-1" / "raw.csv",
    "Raspberry Pi 5": BASE_DIR / "results" / "run-2" / "raw.csv",
}


def sig3(value):
    if value == 0:
        return "0"
    number = Decimal(str(value))
    quantum = Decimal(f"1e{number.adjusted() - 2}")
    return format(number.quantize(quantum, rounding=ROUND_HALF_UP), "f")


for device, filename in files.items():
    groups = defaultdict(list)
    with open(filename, newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            if row["part"].lower() != "aead" or int(row["run"]) == 0:
                continue
            key = (row["algorithm"], int(row["message_bytes"]), row["operation"])
            groups[key].append(int(row["nanoseconds"]))

    results = {}
    for key, times in groups.items():
        median = statistics.median(times) / 1_000_000
        q1, _, q3 = statistics.quantiles(times, n=4)
        iqr = (q3 - q1) / 1_000_000
        results[key] = (sig3(median), sig3(iqr))

    print(f"\n=== {device}: AEAD Benchmarks (ms, 3 significant figures) ===")
    print(f"{'Algorithm':<20} {'Bytes':>9} {'Encrypt Median':>15} {'Encrypt IQR':>12} {'Decrypt Median':>15} {'Decrypt IQR':>12}")
    for algorithm, size in sorted({(algorithm, size) for algorithm, size, _ in results}):
        em, ei = results[(algorithm, size, "encrypt")]
        dm, di = results[(algorithm, size, "decrypt")]
        print(f"{algorithm:<20} {size:>9} {em:>15} {ei:>12} {dm:>15} {di:>12}")
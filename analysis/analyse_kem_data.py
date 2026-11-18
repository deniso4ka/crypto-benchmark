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
            if row["part"].lower() != "kem" or int(row["run"]) == 0:
                continue
            key = (row["algorithm"], row["operation"])
            groups[key].append(int(row["nanoseconds"]))

    results = {}
    for key, times in groups.items():
        median = statistics.median(times) / 1_000_000
        q1, _, q3 = statistics.quantiles(times, n=4)
        iqr = (q3 - q1) / 1_000_000
        results[key] = (sig3(median), sig3(iqr))

    print(f"\n=== {device}: KEM Benchmarks (ms, 3 significant figures) ===")
    print(f"{'Algorithm':<18} {'Keygen Median':>14} {'Keygen IQR':>12} {'Encap Median':>14} {'Encap IQR':>12} {'Decap Median':>14} {'Decap IQR':>12}")
    for algorithm in sorted({algorithm for algorithm, _ in results}):
        values = []
        for operation in ("keygen", "encapsulate", "decapsulate"):
            values.extend(results[(algorithm, operation)])
        print(f"{algorithm:<18} {values[0]:>14} {values[1]:>12} {values[2]:>14} {values[3]:>12} {values[4]:>14} {values[5]:>12}")

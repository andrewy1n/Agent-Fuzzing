import argparse
from pathlib import Path
from typing import List
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import yaml
from ExecStateFuzzer.ql_emulation import execute_with_qiling


MAP_SIZE = 1 << 16


def _run_one_bitmap(fpath: str, run_config: dict) -> bytes:
    data = Path(fpath).read_bytes()
    result = execute_with_qiling(data, run_config)
    bitmap = result.cov_bitmap if result.cov_bitmap is not None else bytearray(MAP_SIZE)
    # Return presence-only bytes to reduce IPC size ambiguity; counts don't matter for union
    return bytes(1 if b else 0 for b in bitmap)


def main():
    parser = argparse.ArgumentParser(description="Compute and compare total edges and Jaccard similarity for two corpora.")
    parser.add_argument("input_dir_a", type=str, help="First directory where each file is an input")
    parser.add_argument("input_dir_b", type=str, help="Second directory where each file is an input")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 1)), help="Number of parallel workers")
    args = parser.parse_args()

    run_config = yaml.safe_load(open("config.yaml"))

    def build_bitmap(input_dir: Path, jobs: int) -> bytearray:
        if not input_dir.is_dir():
            print(f"Input directory not found: {input_dir}")
            raise SystemExit(1)

        # Collect only regular files in the given directory (non-recursive), sorted
        input_files: List[Path] = sorted([p for p in input_dir.iterdir() if p.is_file()])

        cumulative = bytearray(MAP_SIZE)

        with ProcessPoolExecutor(max_workers=max(1, int(jobs))) as executor:
            futures = [executor.submit(_run_one_bitmap, str(f), run_config) for f in input_files]
            for fut in as_completed(futures):
                bm = fut.result()
                # Union presence-only bitmap
                for i in range(MAP_SIZE):
                    if bm[i]:
                        cumulative[i] = 1
        return cumulative

    bitmap_a = build_bitmap(Path(args.input_dir_a), args.jobs)
    bitmap_b = build_bitmap(Path(args.input_dir_b), args.jobs)

    total_edges_a = sum(1 for b in bitmap_a if b)
    total_edges_b = sum(1 for b in bitmap_b if b)
    intersection = sum(1 for a, b in zip(bitmap_a, bitmap_b) if a and b)
    union = sum(1 for a, b in zip(bitmap_a, bitmap_b) if a or b)
    jaccard = (intersection / union) if union else 0.0

    print(f"total_edges_a: {total_edges_a}")
    print(f"total_edges_b: {total_edges_b}")
    print(f"jaccard_similarity: {jaccard:.6f}")
    growth_b_over_a = sum(1 for a, b in zip(bitmap_a, bitmap_b) if (not a) and b)
    growth_b_pct = (growth_b_over_a / total_edges_a * 100.0) if total_edges_a > 0 else (100.0 if growth_b_over_a > 0 else 0.0)
    print(f"coverage_growth_over_a_percent: a=0.00% b={growth_b_pct:.2f}%")


if __name__ == "__main__":
    main()


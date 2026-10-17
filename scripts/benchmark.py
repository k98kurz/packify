"""
Benchmark harness for `packify`. Measures `pack` and `unpack`
throughput over a deterministic corpus and reports the minimum and
median nanoseconds per operation. With `--rev`, each revision's
`packify` package is loaded in an isolated subprocess, making before
and after comparisons reproducible without modifying the working tree.
"""

from __future__ import annotations
from argparse import ArgumentParser, Namespace
from decimal import Decimal
from io import BytesIO
from json import dumps, loads
from packify import pack, unpack
from pathlib import Path
from random import Random
from shutil import rmtree
from statistics import median
from subprocess import TimeoutExpired, run
from tempfile import mkdtemp
from time import perf_counter_ns
from typing import Any, Callable
import gc
import os
import sys
import tarfile


WORKING_TREE = 'working-tree'
_SCRIPT_PATH = Path(__file__).resolve()
_REPO_ROOT = _SCRIPT_PATH.parent.parent


class Wrapper:
    """A minimal `Packable` used to exercise the target code path."""

    def __init__(self, data: Any) -> None:
        self.data = data

    def pack(self) -> bytes:
        return pack(self.data)

    @classmethod
    def unpack(cls, data: bytes, inject: dict = {}) -> Wrapper:
        return cls(unpack(data, inject=inject))


_INJECT = {'Wrapper': Wrapper}


def _random_scalar(rng: Random) -> Any:
    """Returns a deterministic pseudo-random scalar value."""
    kind = rng.randrange(6)
    if kind == 0:
        return rng.randint(-(2**40), 2**40)
    if kind == 1:
        return rng.uniform(-1e6, 1e6)
    if kind == 2:
        return 'x' * rng.randint(0, 50)
    if kind == 3:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 50)))
    if kind == 4:
        return Decimal(str(rng.uniform(-1e6, 1e6)))
    return rng.choice([None, True, False])


def build_corpus(seed: int) -> dict[str, Any]:
    """Builds the deterministic corpus keyed by human readable names.
        Covers every serializable type and boundary of the length
        encoding, plus two entries driven by `seed`.
    """
    rng = Random(seed)
    return {
        'none': None,
        'bool true': True,
        'bool false': False,
        'int 42': 42,
        'int -42': -42,
        'int 255': 255,
        'int 256': 256,
        'int 65535': 65535,
        'int 65536': 65536,
        'int 2**32-1': 2**32 - 1,
        'int 2**32': 2**32,
        'int 2**2040': 2**2040,
        'int -2**2040': -(2**2040),
        'float': 3.141592653589793,
        'decimal': Decimal('123456.789'),
        'str ascii': 'hello world',
        'str unicode': 'h\u00e9llo w\u00f6rld \u2603',
        'str long': 'x' * 300,
        'bytes': b'hello world',
        'bytearray': bytearray(b'hello world'),
        'list ints': list(range(100)),
        'list mixed': [1, 'a', 2.5, None, True, b'x', Decimal('1.5')],
        'tuple ints': tuple(range(50)),
        'set ints': set(range(50)),
        'dict small': {'a': 1, 'b': 2},
        'dict large': {f'key{i}': i for i in range(100)},
        'nested': {
            'users': [
                {'id': i, 'name': f'u{i}', 'tags': (1, 2, 3)}
                for i in range(20)
            ]
        },
        'packable': Wrapper({'a': [1, 2, 3]}),
        'random list': [_random_scalar(rng) for _ in range(40)],
        'random dict': {f'k{i}': _random_scalar(rng) for i in range(40)},
    }


def _measure(
        fn: Callable[[], Any], iterations: int, warmup: int, reps: int
    ) -> dict[str, float]:
    """Times `fn` over `iterations` samples of `reps` calls each and
        returns the minimum and true median nanoseconds per call. An
        empty-loop baseline is subtracted from every sample, and the
        garbage collector is paused for the duration to keep `median`
        unpolluted by collection pauses.
    """
    gc.disable()
    try:
        for _ in range(warmup * reps):
            fn()
        start = perf_counter_ns()
        for _ in range(reps):
            pass
        overhead = (perf_counter_ns() - start) / reps
        samples: list[float] = []
        for _ in range(iterations):
            start = perf_counter_ns()
            for _ in range(reps):
                fn()
            samples.append(max(
                0.0, (perf_counter_ns() - start) / reps - overhead))
    finally:
        gc.enable()
    samples.sort()
    return {
        'min_ns': samples[0],
        'median_ns': median(samples),
    }


def _run_benchmarks(
        direction: str, iterations: int, warmup: int, reps: int, seed: int
    ) -> dict[str, Any]:
    """Measures every corpus value in the requested direction(s)."""
    corpus = build_corpus(seed)
    results: dict[str, Any] = {}
    if direction in ('pack', 'both'):
        results['pack'] = {}
        for name, value in corpus.items():
            results['pack'][name] = _measure(
                lambda v=value: pack(v), iterations, warmup, reps)
    if direction in ('unpack', 'both'):
        results['unpack'] = {}
        for name, value in corpus.items():
            packed = pack(value)
            results['unpack'][name] = _measure(
                lambda p=packed: unpack(p, inject=_INJECT),
                iterations, warmup, reps)
    return results


def _git_archive(rev: str) -> bytes:
    """Returns the tar archive of the `packify` package at `rev`."""
    proc = run(
        ['git', 'archive', '--format=tar', rev, 'packify'],
        cwd=_REPO_ROOT, capture_output=True
    )
    if proc.returncode != 0:
        raise SystemExit(
            f'could not read revision {rev!r}: '
            f'{proc.stderr.decode().strip()}'
        )
    return proc.stdout


def _extract_archive(blob: bytes, dest: Path) -> None:
    """Extracts a tar `blob` into the `dest` directory."""
    with tarfile.open(fileobj=BytesIO(blob)) as tar:
        try:
            tar.extractall(dest, filter='data')
        except TypeError:
            tar.extractall(dest)


def _extract_revision(rev: str) -> Path:
    """Extracts the `packify` package at `rev` into a temporary
        directory and returns that directory.
    """
    dest = Path(mkdtemp(prefix='packify-bench-'))
    _extract_archive(_git_archive(rev), dest)
    return dest


def _spawn_worker(
        label: str, pythonpath: Path, args: Namespace
    ) -> dict[str, Any]:
    """Runs the worker in a subprocess with `packify` resolved from
        `pythonpath` and site packages disabled.
    """
    # `-S` skips site-packages so the revision under test is imported
    # from `pythonpath` alone; this requires packify to remain
    # dependency-free on the runtime path.
    cmd = [
        sys.executable, '-S', str(_SCRIPT_PATH),
        '--worker',
        '--label', label,
        '--direction', args.direction,
        '--iterations', str(args.iterations),
        '--warmup', str(args.warmup),
        '--reps', str(args.reps),
        '--seed', str(args.seed),
    ]
    env = dict(os.environ)
    env['PYTHONPATH'] = str(pythonpath)
    try:
        proc = run(
            cmd, capture_output=True, text=True, env=env, timeout=300)
    except TimeoutExpired:
        raise SystemExit(f'benchmark worker for {label} timed out')
    if proc.returncode != 0:
        raise SystemExit(
            f'benchmark worker for {label} failed:\n{proc.stderr}'
        )
    try:
        return loads(proc.stdout)
    except ValueError as exc:
        raise SystemExit(
            f'benchmark worker for {label} produced invalid JSON:\n'
            f'{exc}\nworker stderr:\n{proc.stderr}'
        )


def _benchmark_revision(rev: str, args: Namespace) -> dict[str, Any]:
    """Benchmarks a single revision, cleaning up any temporary
        checkout afterwards.
    """
    if rev == WORKING_TREE:
        return _spawn_worker(WORKING_TREE, _REPO_ROOT, args)
    path = _extract_revision(rev)
    try:
        return _spawn_worker(rev, path, args)
    finally:
        rmtree(path, ignore_errors=True)


def _worker_main(args: Namespace) -> None:
    """Measures the imported `packify` and writes JSON to stdout."""
    results = _run_benchmarks(
        args.direction, args.iterations, args.warmup, args.reps, args.seed)
    report = {
        'revision': args.label,
        'python': sys.version.split()[0],
        'direction': args.direction,
        'seed': args.seed,
        'reps': args.reps,
        'iterations': args.iterations,
        'results': results,
    }
    sys.stdout.write(dumps(report))


def _format_ns(value: float | None) -> str:
    """Formats a nanosecond value for display."""
    return 'n/a' if value is None else f'{value:,.0f}'


def _print_report(reports: list[dict[str, Any]]) -> None:
    """Prints a comparison table for the collected reports."""
    first = reports[0]
    print(
        f"python {first['python']} | direction {first['direction']} | "
        f"seed {first['seed']} | reps {first['reps']} | "
        f"samples {first['iterations']}"
    )
    labels = [report['revision'] for report in reports]
    for direction in ('pack', 'unpack'):
        if direction not in first['results']:
            continue
        print()
        print(f'{direction} (ns/op, min)')
        if len(reports) == 2:
            print(
                f'speedup = {labels[0]} / {labels[1]}; ratios above '
                f'1.00x mean {labels[1]} is faster'
            )
        names = sorted(first['results'][direction])
        widths = [max(len('workload'), *(len(name) for name in names))]
        widths += [max(len(label), 14) for label in labels]
        if len(reports) == 2:
            widths.append(max(len('speedup'), 8))
        header = 'workload'.ljust(widths[0])
        for index, label in enumerate(labels):
            header += '  ' + label.rjust(widths[index + 1])
        if len(reports) == 2:
            header += '  ' + 'speedup'.rjust(widths[-1])
        print(header)
        print('-' * len(header))
        for name in names:
            row = name.ljust(widths[0])
            mins: list[float | None] = []
            for index, report in enumerate(reports):
                value = report['results'][direction][name]['min_ns']
                mins.append(value)
                row += '  ' + _format_ns(value).rjust(widths[index + 1])
            if len(reports) == 2:
                before, after = mins
                ratio = f'{before / after:.2f}x' if before and after \
                    else 'n/a'
                row += '  ' + ratio.rjust(widths[-1])
            print(row)


def _build_parser() -> ArgumentParser:
    """Builds the command line argument parser."""
    parser = ArgumentParser(
        description='Benchmark packify pack/unpack throughput.'
    )
    parser.add_argument(
        '--direction', choices=('pack', 'unpack', 'both'), default='both',
        help='which operation(s) to benchmark (default: both)'
    )
    parser.add_argument(
        '--rev', action='append', metavar='REV',
        help='git revision to benchmark; repeat to compare revisions; '
             'defaults to the working tree'
    )
    parser.add_argument(
        '--iterations', type=int, default=30,
        help='measured samples per workload (default: 30)'
    )
    parser.add_argument(
        '--warmup', type=int, default=5,
        help='discarded warmup passes of reps calls per workload '
             '(warmup x reps calls total; default: 5)'
    )
    parser.add_argument(
        '--reps', type=int, default=100,
        help='operations per measured sample (default: 100)'
    )
    parser.add_argument(
        '--seed', type=int, default=0,
        help='seed for randomized corpus entries (default: 0)'
    )
    parser.add_argument(
        '--json', metavar='PATH',
        help='write the raw results as JSON to PATH'
    )
    parser.add_argument(
        '--worker', action='store_true', help='(internal) run one revision'
    )
    parser.add_argument(
        '--label', default=WORKING_TREE, help='(internal) worker label'
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Runs the benchmark driver or, with `--worker`, a single run."""
    args = _build_parser().parse_args(argv)
    if args.worker:
        _worker_main(args)
        return
    revisions = args.rev or [WORKING_TREE]
    reports = [_benchmark_revision(rev, args) for rev in revisions]
    _print_report(reports)
    if args.json:
        Path(args.json).write_text(dumps(reports, indent=2))


if __name__ == '__main__':
    main()

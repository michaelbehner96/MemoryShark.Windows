# Memory-range process scanning

The old `long[] Scan(algorithm, signature)` API has been replaced. Scans now require
`ScanOptions` and return `ScanResult`. This is intentionally a breaking change.

## Responsibilities

| Service                                           | Responsibility                                                                      |
|---------------------------------------------------|-------------------------------------------------------------------------------------|
| `WindowsScanner`                                  | Select regions, coordinate reads/matching, cancellation and bounded results         |
| `IMemoryRangeReader` / `WindowsMemoryRangeReader` | Read requested byte ranges in bounded chunks; Windows recovery uses page boundaries |
| `PatternMatchingSession`                          | Maintain boundary continuity and convert buffer-relative matches into addresses     |
| `IPatternMatcher`                                 | Match a buffer using an alignment origin, match cap and cancellation token          |
| `IMemoryIO` / `WindowsMemoryIO`                   | Exact memory transfers; native error and target-exit reporting                      |

All process-related dependencies must refer to the same target. Tests replace the
memory backend, region source, and system-information provider. No inheritance
between the scanner, reader, or matcher is needed.

## Construction and use

```csharp
using MemoryShark.Memory.Reading;
using MemoryShark.Windows.Memory.Reading;

var processHandler = new WindowsProcessHandler(process);
var systemInformationProvider = new WindowsSystemInformationProvider();
var memoryIO = new WindowsMemoryIO(processHandler);
var regionInformationProvider = new WindowsMemoryRegionInformationProvider(processHandler);
var regionEnumerator = new WindowsMemoryRegionEnumerator(regionInformationProvider, systemInformationProvider);
var rangeReader = new WindowsMemoryRangeReader(memoryIO, systemInformationProvider,
    pagesPerRead: 256, readFailurePolicy: MemoryReadFailurePolicy.SkipUnreadable);

var scanner = new WindowsScanner(rangeReader, regionEnumerator,
    region => region.State == MemoryState.Commit
        && (region.Protect & MemoryProtectionFlags.GuardModifierFlag) == 0
        && (region.Protect & (MemoryProtectionFlags.AnyRead | MemoryProtectionFlags.WriteCopy
            | MemoryProtectionFlags.ExecuteWriteCopy)) != 0);

var options = new ScanOptions(maximumMatches: 100_000,
    maximumReportedSkippedRanges: 1000);

ScanResult result = scanner.Scan(new UnalignedPatternMatcher(),
    new byte?[] { 0x48, 0x8B, null, 0x90 }, options, cancellationToken);
```

The operation is synchronous. Run it on a worker task when used by a UI, and pass
the cancellation token into `Scan`, not only into `Task.Run`.

## Byte-range contract

The range reader yields `MemoryReadResult` objects. Each result records the
address and length of a read, with either its bytes or its failure. This describes
the read outcome before pattern matching. `IMemoryIO.ReadMemory` continues to
return bytes on success and throw on failure.

`ReadRange(address, lengthInBytes, cancellationToken)` accepts
a nonnegative address and a byte length with no alignment requirements. Invalid
arguments and address-range overflow are rejected before enumeration starts.
The final byte must not exceed `long.MaxValue`. Zero length yields no results and
performs no reads; cancellation is still checked during enumeration.

The scanner validates that each selected nonempty region fits the supported address
space, then passes its address and byte length directly to the reader. There are no
page checks or page-count conversions. The interface guarantees ordered, contiguous,
positive-length results covering the requested range exactly once on completion.
Every result lies inside the requested range. Sizes may vary, with no required
alignment, maximum chunk size, or recovery granularity exposed to consumers.

The Windows implementation privately uses the system page size and a `pagesPerRead`
limit to bound native reads. It ends full batches at page boundaries, shortening the
first batch for an unaligned start and the last batch to the remaining byte length.
Failed multipage reads are retried in page-bounded portions clipped to the failed
range. Neither ordinary reads nor recovery round outward. A failed read already
contained within one page is not repeated, even when it covers only part of that page.
These choices are not requirements on replacement readers. Returned byte arrays remain valid and
unmodified by the producer after enumeration advances. Consumers treat them as read-only.
Internal pooling is possible, but recycling published arrays would require an explicit
lease/disposal contract; that change cannot safely be hidden from consumers.

`IMemoryIO` and matching also remain byte-based. Only the concrete Windows range
reader needs system page information; neither the interface nor the scanner exposes it.

## Options and memory bounds

`ScanOptions` validates only scan-level match and diagnostic limits. Read configuration
belongs to the reader: the Windows reader accepts `pagesPerRead` and
`MemoryReadFailurePolicy` in its constructor and validates its own byte limit.
The reader interface, read result, and read policy live in `MemoryShark.Memory.Reading`;
the Windows implementation lives in `MemoryShark.Windows.Memory.Reading`.

The scanner never predicts output sizes or allocates matching buffers. The matching
session allocates lazily from actual input plus retained bytes, grows geometrically,
and reuses its largest buffer for the rest of the region. Only retained bytes are
copied when growing. This avoids both speculative allocation and repeated growth
allocations for slightly increasing batches, at the cost of spare capacity and a
temporary overlap between old and new arrays during resizing.

The session checks the actual combined size against `Array.MaxLength` before allocating.
It no longer rejects a small scan merely because a reader's configured maximum plus
the signature would be too large. The combined input must still fit one managed array;
an exceptionally large batch plus its retained tail can be rejected, and allocation
can still fail under memory pressure. No pooling or disposable buffer ownership is introduced.

- The Windows reader defaults to 256 pages per read (1 MiB with 4096-byte pages).
  Its constructor checks page-count multiplication and the supported read buffer size.
  Edge batches can contain partial pages; no bytes outside the requested range are read.
- Default maximum match count is 1,000,000. It must be positive. Matching stops
  inside the current buffer when the remaining result capacity is reached.
- Default skipped-range detail limit is 1000; zero disables individual details.
  Adjacent skipped blocks with the same failure message are consolidated.
  Skipped byte totals remain exact even when details are truncated.
- The Windows reader's page count bounds **new bytes per read**, not total memory usage.
  The session retains up to pattern length minus one bytes, plus spare buffer capacity. Pattern snapshots,
  result lists, and temporary read buffers consume additional memory. Managed
  arrays become eligible for garbage collection; they are not immediately freed.
- Matching uses bounds-checked spans rather than unsafe pointers. The matching
  buffer is reused within a region. `UnalignedPatternMatcher` composes an alignment-one
  `AlignedPatternMatcher` so wildcard and cancellation behavior share one implementation.

## Matching semantics

`WindowsScanner` creates a fresh `PatternMatchingSession` for each region. Its
`ProcessBatch` method retains boundary bytes, invokes an injected `IPatternMatcher`,
and converts the matcher's buffer-relative offsets into process addresses.
`IPatternMatcher.FindMatches` searches only the supplied buffer; it does not retain
previous input. The session composes the matcher rather than implementing its interface.
The session alone owns continuity: a successful input address different from the
expected next address discards the retained tail. The scanner records failed ranges
and passes only successful reads; it does not call a reset method. A new region gets
a new session, so matches never cross region boundaries.

Alignment remains relative to each region's base. The new `FindMatches` signature
accepts the combined buffer's offset from that origin, maximum matches, and a token.
For alignment four and buffer offset 4093, the first eligible buffer index is three.

The session retains a tail shorter than the pattern, supporting patterns spanning
multiple batches without duplicate results. The next successful read after a gap
automatically clears that tail before matching. Every
new region starts fresh: this version intentionally does not match across region
boundaries, even when adjacent regions are readable.

Selected regions retain enumeration order; matches within each region are ascending.
The signature is copied when scanning begins. Custom algorithms must return ordered,
valid indexes and honor the requested result cap and cancellation token.

## Failure and completion behavior

`MemoryReadFailurePolicy` is selected when constructing the Windows reader.

- `Stop`: the first read failure throws. No partial `ScanResult` is returned.
- `SkipUnreadable` (default): partial-copy (299), invalid-address (487), no-access (998), and incomplete-transfer errors
  are recoverable. Named codes are defined in
  `WindowsErrorCode`; the core exception retains a numeric value. A failed multipage batch
  receives one pass of page-bounded reads clipped to its range. A failed read contained
  within a single page is not repeated.
  Valid pages continue through normal matching; unreadable pages become gaps.
- Access denial, invalid handles, observed process exit, region-enumeration failures,
  and unexpected exceptions terminate the scan. They are not reported as skipped pages.
  Custom memory backends must also report process exit as a fatal error.
- `WindowsMemoryIO` verifies native transferred-byte counts on reads and writes.
  Failed reads do not expose partial buffers. `IncompleteMemoryTransferException`
  includes the address, requested count and actual count. A failed write may have
  changed memory; no rollback or automatic write retry is performed.
- `Finished` means all selected regions were traversed. Check `HasCompleteCoverage`
  to distinguish that from finishing with unreadable gaps. Intentionally filtered
  regions are outside the requested coverage and do not count as skipped.
- `MatchLimitReached` means scanning stopped at the configured cap. It does not
  claim additional matches exist: finding exactly the cap also stops the operation.
- `BytesRead` counts successfully delivered bytes once, excluding failed attempts,
  carry bytes and discarded partial transfers. It can include an entire chunk when
  matching stops partway through that chunk. It is not a bytes-compared counter.
- Cancellation throws `OperationCanceledException`, without a partial result. It
  is checked between region queries, reads, recovery steps, and every 1024 byte
  comparisons within matching. A running native call or array copy is not interruptible.
- The scan is not an atomic snapshot. Memory may change between successful reads.

## Verification

From the Windows project directory:

```text
dotnet run --project Tests/Scanning/Scanning.Tests.csproj
dotnet run --project Tests/Scanning/Scanning.Tests.csproj -- --native
```

The dependency-free runner compares scans of aligned and unaligned ranges against an exhaustive reference,
including several alignments, wildcards, long patterns, region-relative offsets,
unreadable gaps, caps and cancellation. The optional native test uses only its own
process: it allocates three pages, marks the middle page inaccessible, verifies
recovery, restores protection and releases the allocation.

Additional regressions substitute readers with arbitrary byte-sized chunks and
failure ranges, and feed non-page-sized chunks directly to the matching session.
They exercise growth, long signatures, overlapping matches, address gaps, alignment,
and the maximum supported address without depending on the Windows batching strategy.
Recovery tests verify clipped edge pages, exact coverage, failures in each intersecting
page, no identical retry of a failed partial-page read, stop policy, incomplete transfers,
and cancellation during recovery. Native tests include an unaligned subrange crossing
an inaccessible page in the test process.

## Ownership review

The scanner operates on byte ranges and does not inspect page size, read size, or
recovery granularity. Reader configuration and output sizing stay with the reader;
the session owns its storage from actual input. Changing Windows batching therefore
does not change the scanner or session while the public range/result contract holds.

Address-range validation in the scanner protects conversion from Windows region
metadata into the library's nonnegative `long` address contract. The reader validates
its own inputs because it can be called independently. Unaligned ranges are valid.
Exact-read enforcement and recoverable-error classification remain in the Windows reader.
Scan limits, skipped-range coalescing, statistics, and completion remain in the scanner.

There is no new factory, manager, shared sizing helper, or configuration wrapper.
Changing read tuning now means constructing a reader with different settings and
injecting it into a scanner. This is an intentional API change from per-scan read settings.
The reader abstraction is platform-neutral; Windows region enumeration remains a
separate Windows-specific dependency of `WindowsScanner`.

using MemoryShark.Memory.Reading;
using MemoryShark.Memory.Regions;
using MemoryShark.Scanning.Algorithms;
using MemoryShark.Scanning.Scanners;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Scanning.Scanners;

public class WindowsScanner : IScanner
{
    private readonly IMemoryRangeReader rangeReader;
    private readonly IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator;
    private readonly Predicate<MemoryBasicInformation> memoryRegionFilter;

    public WindowsScanner(IMemoryRangeReader rangeReader, IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator, Predicate<MemoryBasicInformation> memoryRegionFilter)
    {
        this.rangeReader = rangeReader ?? throw new ArgumentNullException(nameof(rangeReader));
        this.memoryRegionEnumerator = memoryRegionEnumerator ?? throw new ArgumentNullException(nameof(memoryRegionEnumerator));
        this.memoryRegionFilter = memoryRegionFilter ?? throw new ArgumentNullException(nameof(memoryRegionFilter));
    }

    public ScanResult Scan(IPatternMatcher patternMatcher, byte?[] signature, ScanOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(patternMatcher);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(options);

        if (signature.Length is 0)
            throw new ArgumentException("Signature cannot be empty.", nameof(signature));

        cancellationToken.ThrowIfCancellationRequested();

        var pattern = signature.ToArray();
        var matchedAddresses = new List<long>();
        var skippedRanges = new List<SkippedMemoryRange>();
        ulong bytesRead = 0;
        ulong bytesSkipped = 0;
        var skippedDetailsTruncated = false;

        using var regions = memoryRegionEnumerator.EnumerateMemoryRegions().GetEnumerator();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!regions.MoveNext())
                break;

            cancellationToken.ThrowIfCancellationRequested();

            var region = regions.Current;

            if (!memoryRegionFilter(region) || region.RegionSize is 0)
                continue;

            if (region.BaseAddress > long.MaxValue || region.RegionSize - 1 > long.MaxValue - region.BaseAddress)
                throw new InvalidOperationException("A selected region exceeds the supported address range.");

            var regionBaseAddress = (long)region.BaseAddress;
            var matchingSession = new PatternMatchingSession(patternMatcher, pattern, regionBaseAddress);

            foreach (var memoryReadResult in rangeReader.ReadRange(regionBaseAddress, region.RegionSize, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (memoryReadResult.Data == null)
                {
                    bytesSkipped = checked(bytesSkipped + (ulong)memoryReadResult.LengthInBytes);
                    if (!RecordSkippedRange(skippedRanges, memoryReadResult, options.MaximumReportedSkippedRanges))
                        skippedDetailsTruncated = true;

                    continue;
                }

                bytesRead = checked(bytesRead + (ulong)memoryReadResult.LengthInBytes);

                var remainingMatchCapacity = options.MaximumMatches - matchedAddresses.Count;

                matchedAddresses.AddRange(matchingSession.ProcessBatch(memoryReadResult.Address, memoryReadResult.Data, remainingMatchCapacity, cancellationToken));

                if (matchedAddresses.Count == options.MaximumMatches)
                    return new ScanResult(matchedAddresses, skippedRanges, ScanCompletionReason.MatchLimitReached, bytesRead, bytesSkipped, skippedDetailsTruncated);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        return new ScanResult(matchedAddresses, skippedRanges, ScanCompletionReason.Finished, bytesRead, bytesSkipped, skippedDetailsTruncated);
    }

    private static bool RecordSkippedRange(List<SkippedMemoryRange> ranges, MemoryReadResult block, int maximumRanges)
    {
        var reason = block.ReadFailure!.Message;

        if (ranges.Count > 0)
        {
            var previous = ranges[^1];

            if ((ulong)previous.Address + previous.LengthInBytes == (ulong)block.Address && previous.Reason == reason)
            {
                ranges[^1] = previous with { LengthInBytes = checked(previous.LengthInBytes + (ulong)block.LengthInBytes) };

                return true;
            }
        }

        if (ranges.Count == maximumRanges)
            return false;
        ranges.Add(new SkippedMemoryRange(block.Address, (ulong)block.LengthInBytes, reason));

        return true;
    }
}
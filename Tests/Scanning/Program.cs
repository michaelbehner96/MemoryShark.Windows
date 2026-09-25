using MemoryShark.Windows.Providers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Memory;
using MemoryShark.Memory.Reading;
using MemoryShark.Windows.Memory.Reading;
using MemoryShark.Memory.Regions;
using MemoryShark.Scanning.Algorithms;
using MemoryShark.Scanning.Scanners;
using MemoryShark.Windows.Memory;
using MemoryShark.Windows.Memory.Allocation;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Processes;
using MemoryShark.Windows.Scanning.Scanners;

internal static class Program
{
    private static int assertions;
    private static void Main(string[] arguments)
    {
        TestAgainstReference();
        TestRecovery();
        TestRangeContract();
        TestPartialPageRecovery();
        TestLimitsAndCancellation();
        TestVariableBatchReader();
        TestMatchingSession();
        if (arguments.Contains("--native")) TestNativeReads();
        Console.WriteLine($"Passed {assertions} scanner assertions.");
    }

    private static void TestAgainstReference()
    {
        var random = new Random(93);
        for (int iteration = 0; iteration < 250; iteration++)
        {
            byte[] data = new byte[random.Next(64, 257)];
            random.NextBytes(data);
            byte?[] pattern = new byte?[random.Next(1, 50)];
            for (int index = 0; index < pattern.Length; index++)
                pattern[index] = random.Next(3) == 0 ? null : (byte)random.Next(256);
            int plantedOffset = random.Next(data.Length - pattern.Length + 1);
            for (int index = 0; index < pattern.Length; index++)
                if (pattern[index].HasValue) data[plantedOffset + index] = pattern[index]!.Value;
            long baseAddress = 4096 + iteration % 16;
            int? failedPage = iteration % 3 == 0 ? 258 : null;

            foreach (uint alignment in new uint[] { 1, 3, 4, 7, uint.MaxValue })
            {
                var expected = new List<long>();
                for (long index = 0; index <= data.Length - pattern.Length; index += alignment)
                {
                    bool matches = true;
                    for (int patternIndex = 0; patternIndex < pattern.Length; patternIndex++)
                    {
                        long address = baseAddress + index + patternIndex;
                        if (address / 16 == failedPage ||
                            (pattern[patternIndex].HasValue && pattern[patternIndex] != data[(int)index + patternIndex]))
                        {
                            matches = false;
                            break;
                        }
                    }
                    if (matches) expected.Add(baseAddress + index);
                }
                foreach (int pagesPerRead in new[] { 1, 2, 4 })
                {
                    var memory = new TestMemory(baseAddress, data) { FailedPage = failedPage };
                    ScanResult result = CreateScanner(memory, pagesPerRead).Scan(new AlignedPatternMatcher(alignment), pattern,
                        new ScanOptions());
                    Assert(result.Matches.SequenceEqual(expected), $"Reference mismatch {iteration}/{alignment}/{pagesPerRead}.");
                    Assert(result.BytesRead + result.BytesSkipped == (ulong)data.Length, "Coverage accounting.");
                    Assert(memory.Reads.All(read => read.Address >= baseAddress && read.Length > 0
                        && read.Address + read.Length <= baseAddress + data.Length && read.Length <= pagesPerRead * 16),
                        "Every read must stay inside the requested range and configured size limit.");
                }
            }
        }
        var memoryWithDuplicates = new TestMemory(4096, Enumerable.Repeat((byte)1, 64).ToArray());
        ScanResult overlapping = CreateScanner(memoryWithDuplicates).Scan(new UnalignedPatternMatcher(), new byte?[] { 1, 1, 1 },
            new ScanOptions());
        Assert(overlapping.Matches.SequenceEqual(Enumerable.Range(4096, 62).Select(value => (long)value)),
            "Overlapping matches must not be lost or duplicated.");
        var splitMemory = new TestMemory(4096, Enumerable.Repeat((byte)1, 32).ToArray());
        var scanner = new WindowsScanner(new WindowsMemoryRangeReader(splitMemory, new TestSystemInformation()),
            new TestRegions(Region(4096, 16), Region(4112, 16)), region => true);
        ScanResult split = scanner.Scan(new UnalignedPatternMatcher(), new byte?[] { 1, 1 }, new ScanOptions());
        Assert(split.Matches.Count == 30 && !split.Matches.Contains(4111), "Do not carry across regions.");
    }

    private static void TestRecovery()
    {
        var options = new ScanOptions();
        var memory = new TestMemory(4096, Enumerable.Repeat((byte)1, 64).ToArray()) { FailedPage = 257 };
        ScanResult result = CreateScanner(memory, pagesPerRead: 2).Scan(new UnalignedPatternMatcher(), new byte?[] { 1, 1 }, options);
        Assert(result.BytesRead == 48 && result.BytesSkipped == 16, "Recover readable pages.");
        Assert(result.SkippedRanges.Count == 1 && result.SkippedRanges[0].Address == 4112, "Report failed page.");
        Assert(!result.Matches.Contains(4111) && !result.Matches.Contains(4127), "No matches across gaps.");
        Assert(result.CompletionReason == ScanCompletionReason.Finished && !result.HasCompleteCoverage, "Report incomplete coverage.");
        Assert(memory.Reads.Count == 4, "Recovery attempts must be bounded.");
        memory = new TestMemory(4096, new byte[64]) { Failure = new PinvokeException("ReadProcessMemory", 299) };
        result = CreateScanner(memory, pagesPerRead: 2).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options);
        Assert(result.BytesSkipped == 64 && result.SkippedRanges.Single().LengthInBytes == 64, "Merge consecutive failures.");
        Assert(memory.Reads.Count == 6, "Do not retry individual pages indefinitely.");
        memory = new TestMemory(4096, new byte[64]) { FailedPage = 257 };
        Expect<PinvokeException>(() => CreateScanner(memory, pagesPerRead: 2, readFailurePolicy: MemoryReadFailurePolicy.Stop)
            .Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options));
        Assert(memory.Reads.Count == 1, "Stop policy must not recover.");

        foreach (Exception failure in new Exception[]
        {
            new PinvokeException("ReadProcessMemory", 5), new PinvokeException("ReadProcessMemory", 6),
            new InvalidOperationException("Target process exited"), new ArgumentException("Backend bug")
        })
        {
            memory = new TestMemory(4096, new byte[64]) { Failure = failure };
            Exception caught = Expect<Exception>(() => CreateScanner(memory, pagesPerRead: 2).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options));
            Assert(ReferenceEquals(caught, failure) && memory.Reads.Count == 1, "Fatal error must propagate unchanged.");
        }
        memory = new TestMemory(4096, new byte[32]) { ReturnShortBuffers = true };
        result = CreateScanner(memory, pagesPerRead: 2).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options);
        Assert(result.BytesRead == 0 && result.BytesSkipped == 32 && result.Matches.Count == 0, "Never scan short buffers.");
        Expect<IncompleteMemoryTransferException>(() => CreateScanner(memory, pagesPerRead: 1, readFailurePolicy: MemoryReadFailurePolicy.Stop)
            .Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options));
    }

    private static void TestRangeContract()
    {
        var memory = new TestMemory(4096, new byte[80]);
        var reader = new WindowsMemoryRangeReader(memory, new TestSystemInformation(), pagesPerRead: 2);
        var options = new ScanOptions();
        Expect<ArgumentOutOfRangeException>(() => reader.ReadRange(-16, 1));
        Expect<ArgumentOutOfRangeException>(() => reader.ReadRange(4096, ulong.MaxValue));
        Expect<ArgumentOutOfRangeException>(() => reader.ReadRange(long.MaxValue - 15, 17));
        Assert(!reader.ReadRange(4097, 0).Any() && memory.Reads.Count == 0,
            "Zero length and rejected arguments must perform no reads.");

        var blocks = reader.ReadRange(4096, lengthInBytes: 80).ToArray();
        Assert(blocks.Select(block => block.LengthInBytes).SequenceEqual(new[] { 32, 32, 16 }),
            "The final batch contains the remaining whole page.");
        Assert(memory.Reads.Select(read => read.Address).SequenceEqual(new long[] { 4096, 4128, 4160 }),
            "The requested byte range is covered by contiguous reads.");

        foreach (var unalignedRegion in new[] { Region(4097, 16), Region(4096, 17) })
        {
            var regionMemory = new TestMemory((long)unalignedRegion.BaseAddress, new byte[(int)unalignedRegion.RegionSize]);
            var scan = CreateScanner(regionMemory).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, options);
            Assert(scan.HasCompleteCoverage && scan.BytesRead == unalignedRegion.RegionSize
                && scan.Matches.Count == (int)unalignedRegion.RegionSize, "Scan unaligned ranges without page conversion.");
        }

        var finalPageMemory = new TestMemory(long.MaxValue - 15, new byte[16]);
        var finalPageReader = new WindowsMemoryRangeReader(finalPageMemory, new TestSystemInformation());
        Assert(finalPageReader.ReadRange(long.MaxValue - 15, 16).Single().LengthInBytes == 16,
            "A whole page ending at the maximum supported address is valid.");
        Assert(finalPageReader.ReadRange(long.MaxValue, 1).Single().Address == long.MaxValue,
            "A single byte at the maximum supported address is valid.");
        Assert(!finalPageReader.ReadRange(long.MaxValue, 0).Any(), "Empty range at the maximum address.");
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Expect<OperationCanceledException>(() => reader.ReadRange(4097, 0, canceled.Token).ToArray());
    }

    private static void TestPartialPageRecovery()
    {
        // This request includes 11 bytes of the first page, a whole page, and 7 bytes of the last.
        const long address = 4101;
        const int length = 34;
        foreach (int failedPage in new[] { 256, 257, 258 })
        {
            var memory = new TestMemory(address, Enumerable.Repeat((byte)1, length).ToArray()) { FailedPage = failedPage };
            var reader = new WindowsMemoryRangeReader(memory, new TestSystemInformation(), pagesPerRead: 3);
            var results = reader.ReadRange(address, length).ToArray();
            Assert(results.Select(result => (result.Address, result.LengthInBytes)).SequenceEqual(
                new[] { (4101L, 11), (4112L, 16), (4128L, 7) }), "Recovery clips both edge pages to the request.");
            Assert(results.Count(result => result.Data == null) == 1
                && results.Single(result => result.Data == null).Address / 16 == failedPage,
                "Only the failed page intersection is reported as a gap.");
            Assert(results.Where(result => result.Data != null).All(result => result.Data!.Length == result.LengthInBytes),
                "Recovery exposes only complete successful reads.");
            Assert(memory.Reads.Count == 4 && memory.Reads.All(read => read.Address >= address
                && read.Address + read.Length <= address + length), "Native attempts stay inside the requested range.");
        }

        var failedMemory = new TestMemory(address, new byte[length])
            { Failure = new PinvokeException("ReadProcessMemory", (long)WindowsErrorCode.PartialCopy) };
        var failedScan = CreateScanner(failedMemory, pagesPerRead: 3)
            .Scan(new UnalignedPatternMatcher(), new byte?[] { 0 }, new ScanOptions());
        Assert(failedScan.BytesSkipped == length && failedScan.BytesRead == 0 && failedScan.Matches.Count == 0
            && failedScan.SkippedRanges.Single().Address == address
            && failedScan.SkippedRanges.Single().LengthInBytes == length, "Coalesce partial edge failures into exact range coverage.");

        failedMemory.Reads.Clear();
        var failedReader = new WindowsMemoryRangeReader(failedMemory, new TestSystemInformation());
        Assert(failedReader.ReadRange(address, 3).Single().ReadFailure != null && failedMemory.Reads.Count == 1,
            "A failed partial-page read is not repeated.");
        failedMemory.Reads.Clear();
        var stopReader = new WindowsMemoryRangeReader(failedMemory, new TestSystemInformation(), readFailurePolicy: MemoryReadFailurePolicy.Stop);
        Expect<PinvokeException>(() => stopReader.ReadRange(address, length).ToArray());
        Assert(failedMemory.Reads.Count == 1, "Stop policy performs no partial-page recovery.");

        var shortMemory = new TestMemory(address, new byte[length]) { ReturnShortBuffers = true };
        var shortResults = new WindowsMemoryRangeReader(shortMemory, new TestSystemInformation()).ReadRange(address, length).ToArray();
        Assert(shortResults.All(result => result.Data == null) && shortResults.Sum(result => result.LengthInBytes) == length,
            "Incomplete edge reads never expose partial data as success.");

        using var cancellation = new CancellationTokenSource();
        var canceledMemory = new TestMemory(address, new byte[length]) { FailedPage = 257, AfterRead = () => cancellation.Cancel() };
        var canceledReader = new WindowsMemoryRangeReader(canceledMemory, new TestSystemInformation());
        Expect<OperationCanceledException>(() => canceledReader.ReadRange(address, length, cancellation.Token).ToArray());
        Assert(canceledMemory.Reads.Count == 2, "Cancellation during recovery prevents subsequent page reads.");
    }

    private static void TestLimitsAndCancellation()
    {
        var memory = new TestMemory(4096, new byte[128]);
        ScanResult limited = CreateScanner(memory).Scan(new UnalignedPatternMatcher(), new byte?[] { null },
            new ScanOptions(maximumMatches: 3));
        Assert(limited.Matches.SequenceEqual(new long[] { 4096, 4097, 4098 }), "Match cap.");
        Assert(limited.CompletionReason == ScanCompletionReason.MatchLimitReached && memory.Reads.Count == 1, "Stop at cap.");
        memory = new TestMemory(4096, new byte[64]) { FailOddPages = true };
        ScanResult diagnostics = CreateScanner(memory).Scan(new UnalignedPatternMatcher(), new byte?[] { 1 },
            new ScanOptions(maximumReportedSkippedRanges: 1));
        Assert(diagnostics.SkippedRanges.Count == 1 && diagnostics.SkippedRangeDetailsTruncated
            && diagnostics.BytesSkipped == 32, "Cap details without losing byte totals.");
        Expect<ArgumentOutOfRangeException>(() => CreateScanner(memory, pagesPerRead: 0));
        Expect<ArgumentOutOfRangeException>(() => CreateScanner(memory, pagesPerRead: -1));
        Expect<ArgumentOutOfRangeException>(() => new ScanOptions(maximumMatches: 0));
        Expect<ArgumentOutOfRangeException>(() => new ScanOptions(maximumMatches: -1));
        Expect<ArgumentOutOfRangeException>(() => new ScanOptions(maximumReportedSkippedRanges: -1));
        Expect<ArgumentOutOfRangeException>(() => CreateScanner(memory, readFailurePolicy: (MemoryReadFailurePolicy)99));
        Assert(new ScanOptions(maximumReportedSkippedRanges: 0).MaximumReportedSkippedRanges == 0,
            "Zero diagnostic capacity is a valid configuration.");
        Expect<ArgumentException>(() => CreateScanner(memory).Scan(new UnalignedPatternMatcher(), Array.Empty<byte?>(), new ScanOptions()));
        Expect<ArgumentNullException>(() => CreateScanner(memory).Scan(new UnalignedPatternMatcher(), null!, new ScanOptions()));
        var reader = new WindowsMemoryRangeReader(memory, new TestSystemInformation(), pagesPerRead: 2);
        var defaultOptions = new ScanOptions();
        Assert(defaultOptions.MaximumMatches == 1_000_000 && defaultOptions.MaximumReportedSkippedRanges == 1000,
            "Preserve scan configuration defaults.");
        Expect<OverflowException>(() => CreateScanner(memory, pagesPerRead: int.MaxValue));
        Expect<ArgumentOutOfRangeException>(() => CreateScanner(memory, pagesPerRead: Array.MaxLength / 16 + 1));
        var smallMemory = new TestMemory(4096, new byte[64]);
        var smallScan = CreateScanner(smallMemory, pagesPerRead: Array.MaxLength / 16)
            .Scan(new UnalignedPatternMatcher(), new byte?[1024], new ScanOptions());
        Assert(smallScan.Matches.Count == 0 && smallScan.BytesRead == 64,
            "Matching storage depends on actual input, not the reader's configured maximum.");
        Expect<ArgumentOutOfRangeException>(() => reader.ReadRange(long.MaxValue, 2));
        Assert(new AlignedPatternMatcher(4).FindMatches(new byte[8], new byte?[] { null }, 4093, 10)
            .SequenceEqual(new long[] { 3, 7 }), "Alignment phase.");

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        memory = new TestMemory(4096, new byte[64]);
        Expect<OperationCanceledException>(() => CreateScanner(memory).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 },
            new ScanOptions(), canceled.Token));
        Assert(memory.Reads.Count == 0, "Pre-cancellation performs no reads.");
        using var duringRead = new CancellationTokenSource();
        memory.AfterRead = () => duringRead.Cancel();
        Expect<OperationCanceledException>(() => CreateScanner(memory).Scan(new UnalignedPatternMatcher(), new byte?[] { 0 },
            new ScanOptions(), duringRead.Token));
        Assert(memory.Reads.Count == 1, "Cancel after read.");
        using var duringComparison = new CancellationTokenSource();
        byte[] source = new byte[100_000];
        byte?[] pattern = new byte?[50_000];
        duringComparison.CancelAfter(10);
        Expect<OperationCanceledException>(() => new UnalignedPatternMatcher().FindMatches(source, pattern, 0, int.MaxValue, duringComparison.Token));
    }

    private static void TestVariableBatchReader()
    {
        // Both readers describe the same data and gap using different batch boundaries.
        // Positive sizes are successful reads; negative sizes describe unreadable ranges.
        foreach (var layout in new[]
        {
            new[] { 16, 4800, -32, -48, 6400, 16 },
            new[] { 1024, 3792, -80, 2048, 4368 },
            new[] { 7, 4809, -31, -49, 6415, 1 }
        })
        {
            var results = new List<MemoryReadResult>();
            long address = 4099;
            foreach (int signedLength in layout)
            {
                int length = Math.Abs(signedLength);
                results.Add(signedLength > 0
                    ? new MemoryReadResult(address, length, Enumerable.Repeat((byte)1, length).ToArray(), null)
                    : new MemoryReadResult(address, length, null, new InvalidOperationException("Unreadable test range")));
                address += length;
            }

            const int regionLength = 11312;
            var expected = Enumerable.Range(0, regionLength - 50 + 1)
                .Where(offset => offset % 3 == 0 && (offset + 50 <= 4816 || offset >= 4896))
                .Select(offset => 4099L + offset).ToArray();
            var reader = new TestVariableRangeReader(results.ToArray());
            var scanner = new WindowsScanner(reader, new TestRegions(Region(4099, regionLength)), region => true);
            var result = scanner.Scan(new AlignedPatternMatcher(3), Enumerable.Repeat<byte?>(1, 50).ToArray(), new ScanOptions());
            Assert(result.Matches.SequenceEqual(expected), "Variable batch sizes preserve matching and gap boundaries.");
            Assert(result.BytesRead == 11232 && result.BytesSkipped == 80, "Variable reader coverage accounting.");
            Assert(result.SkippedRanges.Count == 1 && result.SkippedRanges[0].Address == 8915
                && result.SkippedRanges[0].LengthInBytes == 80, "Multipage failures coalesce independently of batching.");
            Assert(!result.HasCompleteCoverage && result.CompletionReason == ScanCompletionReason.Finished,
                "Variable reader reports completed traversal with gaps.");

            var limited = scanner.Scan(new UnalignedPatternMatcher(), new byte?[] { 1 }, new ScanOptions(maximumMatches: 7));
            Assert(limited.Matches.SequenceEqual(Enumerable.Range(4099, 7).Select(value => (long)value))
                && limited.CompletionReason == ScanCompletionReason.MatchLimitReached, "Variable reader respects scan match limits.");
        }

        foreach (var invalidRegion in new[]
        {
            new MemoryBasicInformation { BaseAddress = (ulong)long.MaxValue + 1, RegionSize = 1 },
            Region(long.MaxValue, 2)
        })
        {
            var reader = new TestVariableRangeReader(Array.Empty<MemoryReadResult>());
            Expect<InvalidOperationException>(() => new WindowsScanner(reader, new TestRegions(invalidRegion), region => true)
                .Scan(new UnalignedPatternMatcher(), new byte?[] { 1 }, new ScanOptions()));
        }
    }

    private static void TestMatchingSession()
    {
        var random = new Random(417);
        for (int iteration = 0; iteration < 100; iteration++)
        {
            var source = new byte[400];
            random.NextBytes(source);
            byte?[] pattern = source.AsSpan(75, 61).ToArray().Select(value => (byte?)value).ToArray();
            for (int index = 0; index < pattern.Length; index += 4) pattern[index] = null;
            uint alignment = (uint)(iteration % 7 + 1);
            var expected = new List<long>();
            for (int offset = 0; offset <= source.Length - pattern.Length; offset++)
            {
                if (offset % alignment != 0) continue;
                bool matches = true;
                for (int index = 0; index < pattern.Length; index++)
                    if (pattern[index].HasValue && pattern[index] != source[offset + index]) matches = false;
                if (matches) expected.Add(4099L + offset);
            }

            var session = new PatternMatchingSession(new AlignedPatternMatcher(alignment), pattern, 4099);
            var actual = new List<long>();
            int consumed = 0;
            while (consumed < source.Length)
            {
                int count = Math.Min(random.Next(1, 31), source.Length - consumed);
                actual.AddRange(session.ProcessBatch(4099 + consumed, source.AsSpan(consumed, count).ToArray(), 1000));
                consumed += count;
            }
            Assert(actual.SequenceEqual(expected), "Arbitrary byte batches preserve long patterns, offsets, and alignment.");
        }

        var growthSession = new PatternMatchingSession(new UnalignedPatternMatcher(), new byte?[] { 1, 1, 1 }, 100);
        var matchesAcrossGrowth = new List<long>();
        long nextAddress = 100;
        foreach (int count in new[] { 1, 2, 1, 128, 3, 1024, 1 })
        {
            matchesAcrossGrowth.AddRange(growthSession.ProcessBatch(nextAddress, Enumerable.Repeat((byte)1, count).ToArray(), 2000));
            nextAddress += count;
        }
        Assert(matchesAcrossGrowth.SequenceEqual(Enumerable.Range(100, (int)(nextAddress - 100 - 2)).Select(value => (long)value)),
            "Buffer growth preserves overlapping matches without duplicates.");

        var gapSession = new PatternMatchingSession(new UnalignedPatternMatcher(), new byte?[] { 1, 2, 3 }, 100);
        Assert(gapSession.ProcessBatch(100, new byte[] { 1, 2 }, 10).Length == 0, "Retain incomplete signature.");
        Assert(gapSession.ProcessBatch(103, new byte[] { 3 }, 10).Length == 0, "Address gap alone clears continuity.");
        Assert(gapSession.ProcessBatch(104, new byte[] { 1, 2, 3 }, 10).SequenceEqual(new long[] { 104 }), "Resume after a gap.");
        Expect<ArgumentOutOfRangeException>(() => gapSession.ProcessBatch(long.MaxValue, new byte[2], 10));
        Expect<ArgumentOutOfRangeException>(() => gapSession.ProcessBatch(99, new byte[1], 10));
        Expect<ArgumentOutOfRangeException>(() => gapSession.ProcessBatch(107, new byte[1], 0));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Expect<OperationCanceledException>(() => gapSession.ProcessBatch(107, new byte[1], 10, cancellation.Token));
        var finalAddressSession = new PatternMatchingSession(new UnalignedPatternMatcher(), new byte?[] { 1 }, long.MaxValue);
        Assert(finalAddressSession.ProcessBatch(long.MaxValue, new byte[] { 1 }, 10).Single() == long.MaxValue,
            "A match ending at the maximum supported address is valid.");
    }

    private static void TestNativeReads()
    {
        using Process process = Process.GetCurrentProcess();
        var handler = new WindowsProcessHandler(process);
        var provider = new WindowsSystemInformationProvider();
        int pageSize = checked((int)provider.GetSystemInformation().PageSize);
        var allocator = new WindowsMemoryAllocator(handler);
        var deallocator = new WindowsMemoryDeallocator(handler);
        var memory = new WindowsMemoryIO(handler);
        long address = allocator.Allocate(null, checked((uint)(pageSize * 3)));
        bool protectionChanged = false;
        uint previousProtection = 0;
        try
        {
            byte[] bytes = new byte[pageSize * 3];
            bytes[0] = 0xAB;
            bytes[pageSize * 2] = 0xAB;
            memory.WriteMemory(address, bytes);
            Assert(memory.ReadMemory(address, (ulong)bytes.Length).SequenceEqual(bytes), "Native exact read/write.");
            protectionChanged = VirtualProtectEx(process.Handle, new IntPtr(address + pageSize),
                new UIntPtr((uint)pageSize), 0x01, out previousProtection);
            Assert(protectionChanged, "Protect middle page.");
            var scanner = new WindowsScanner(new WindowsMemoryRangeReader(memory, provider, pagesPerRead: 3),
                new TestRegions(Region(address, (ulong)bytes.Length)), region => true);
            ScanResult result = scanner.Scan(new UnalignedPatternMatcher(), new byte?[] { 0xAB },
                new ScanOptions());
            Assert(result.Matches.SequenceEqual(new[] { address, address + pageSize * 2 }), "Native page recovery.");
            Assert(result.BytesSkipped == (ulong)pageSize && result.BytesRead == (ulong)(pageSize * 2), "Native coverage.");
            var partialRangeScanner = new WindowsScanner(new WindowsMemoryRangeReader(memory, provider, pagesPerRead: 3),
                new TestRegions(Region(address + 1, (ulong)(bytes.Length - 2))), region => true);
            var partialResult = partialRangeScanner.Scan(new UnalignedPatternMatcher(), new byte?[] { 0xAB }, new ScanOptions());
            Assert(partialResult.Matches.SequenceEqual(new[] { address + pageSize * 2 }), "Native unaligned range recovery.");
            Assert(partialResult.BytesSkipped == (ulong)pageSize && partialResult.BytesRead == (ulong)(pageSize * 2 - 2),
                "Native partial edge pages have exact coverage.");
        }
        finally
        {
            if (protectionChanged)
                VirtualProtectEx(process.Handle, new IntPtr(address + pageSize), new UIntPtr((uint)pageSize), previousProtection, out _);
            deallocator.Deallocate(address);
        }
        Console.WriteLine("Native read/write and inaccessible-page recovery passed in the test process; allocation released.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(IntPtr process, IntPtr address, UIntPtr size, uint protection, out uint previousProtection);
    private static WindowsScanner CreateScanner(TestMemory memory, int pagesPerRead = 1,
        MemoryReadFailurePolicy readFailurePolicy = MemoryReadFailurePolicy.SkipUnreadable) => new(
        new WindowsMemoryRangeReader(memory, new TestSystemInformation(), pagesPerRead, readFailurePolicy),
        new TestRegions(Region(memory.BaseAddress, (ulong)memory.Data.Length)), region => true);
    private static MemoryBasicInformation Region(long address, ulong length) => new()
        { BaseAddress = (ulong)address, RegionSize = length, State = MemoryState.Commit };
    private static void Assert(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new Exception(message);
    }
    private static TException Expect<TException>(Action action) where TException : Exception
    {
        assertions++;
        try { action(); }
        catch (TException exception) { return exception; }
        throw new Exception($"Expected {typeof(TException).Name}.");
    }
}

internal sealed class TestMemory : IMemoryIO
{
    public long BaseAddress { get; }
    public byte[] Data { get; }
    public int? FailedPage { get; init; }
    public bool FailOddPages { get; init; }
    public bool ReturnShortBuffers { get; init; }
    public Exception? Failure { get; init; }
    public Action? AfterRead { get; set; }
    public List<(long Address, int Length)> Reads { get; } = new();
    public TestMemory(long baseAddress, byte[] data) { BaseAddress = baseAddress; Data = data; }
    public byte[] ReadMemory(long address, ulong length)
    {
        Reads.Add((address, (int)length));
        if (Failure != null) throw Failure;
        for (long page = address / 16; page <= checked(address + ((long)length - 1)) / 16; page++)
            if (page == FailedPage || (FailOddPages && page % 2 != 0))
                throw new PinvokeException("ReadProcessMemory", 299);
        int returnedLength = (int)length - (ReturnShortBuffers ? 1 : 0);
        byte[] result = Data.AsSpan(checked((int)(address - BaseAddress)), returnedLength).ToArray();
        AfterRead?.Invoke();
        return result;
    }
    public void WriteMemory(long address, params byte[] value) => throw new NotSupportedException();
}
internal sealed class TestRegions : IMemoryRegionEnumerator<MemoryBasicInformation>
{
    private readonly MemoryBasicInformation[] regions;
    public TestRegions(params MemoryBasicInformation[] regions) { this.regions = regions; }
    public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions() => regions;
}
internal sealed class TestSystemInformation : IWindowsSystemInformationProvider
{
    public SystemInformation GetSystemInformation() => new() { PageSize = 16 };
}

internal sealed class TestVariableRangeReader : IMemoryRangeReader
{
    private readonly MemoryReadResult[] results;
    public TestVariableRangeReader(MemoryReadResult[] results)
    {
        this.results = results;
    }

    public IEnumerable<MemoryReadResult> ReadRange(long address, ulong lengthInBytes,
        CancellationToken cancellationToken = default)
    {
        if (address < 0) throw new ArgumentOutOfRangeException(nameof(address));
        if (lengthInBytes > 0 && lengthInBytes - 1 > (ulong)(long.MaxValue - address))
            throw new ArgumentOutOfRangeException(nameof(lengthInBytes));
        if (lengthInBytes == 0) return EnumerateResults(Array.Empty<MemoryReadResult>(), cancellationToken);
        ulong describedBytes = 0;
        foreach (var result in results)
        {
            if ((ulong)result.Address != (ulong)address + describedBytes)
                throw new InvalidOperationException("Invalid test-reader layout.");
            describedBytes += (ulong)result.LengthInBytes;
        }
        if (describedBytes != lengthInBytes)
            throw new InvalidOperationException("Test-reader layout does not cover the requested range.");
        return EnumerateResults(results, cancellationToken);
    }

    private static IEnumerable<MemoryReadResult> EnumerateResults(IEnumerable<MemoryReadResult> results, CancellationToken cancellationToken)
    {
        foreach (var result in results)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return result;
        }
        cancellationToken.ThrowIfCancellationRequested();
    }
}

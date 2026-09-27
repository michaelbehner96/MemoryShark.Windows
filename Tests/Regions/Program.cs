using System.Diagnostics;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Reading;
using MemoryShark.Memory.Regions;
using MemoryShark.Providers;
using MemoryShark.Scanning.Algorithms;
using MemoryShark.Scanning.Scanners;
using MemoryShark.Windows.Memory.Allocation;
using MemoryShark.Windows.Memory.Regions;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Processes;
using MemoryShark.Windows.Providers;
using MemoryShark.Windows.Scanning.Scanners;

internal static class Program
{
    private static int assertions;
    private static void Main(string[] arguments)
    {
        TestTraversal();
        TestInvalidResults();
        TestCancellation();
        TestCallerTokenPropagation();
        if (arguments.Contains("--native")) TestNativeQueries();
        Console.WriteLine($"Passed {assertions} region-enumeration assertions.");
    }

    private static void TestTraversal()
    {
        var provider = new RegionProvider(address => Region((ulong)(address / 16 * 16), 16));
        var regions = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(17, 48)).EnumerateMemoryRegions().ToArray();
        Assert(provider.Queries.SequenceEqual(new long[] { 17, 32, 48 }), "Advance from returned base and query the inclusive endpoint.");
        Assert(regions.Select(region => region.BaseAddress).SequenceEqual(new ulong[] { 16, 32, 48 }), "Preserve returned metadata without clipping.");
        Assert(new WindowsMemoryRegionEnumerator(new RegionProvider(_ => Region(16, 16)), new SystemProvider(17, 17))
            .EnumerateMemoryRegions().Count() == 1, "Equal bounds describe one address.");
        var highProvider = new RegionProvider(_ => Region((ulong)long.MaxValue - 15, 16));
        Assert(new WindowsMemoryRegionEnumerator(highProvider, new SystemProvider(long.MaxValue - 15, long.MaxValue))
            .EnumerateMemoryRegions().Single().RegionSize == 16 && highProvider.Queries.Count == 1, "Stop without overflowing the final address.");
        Assert(new WindowsMemoryRegionEnumerator(new RegionProvider(_ => Region(0, (ulong)long.MaxValue + 1)), new SystemProvider(0, long.MaxValue))
            .EnumerateMemoryRegions().Single().BaseAddress == 0, "An unsigned size can cover the entire supported address space.");
        var random = new Random(782);
        for (int iteration = 0; iteration < 100; iteration++)
        {
            long maximum = random.Next(64, 4096);
            var expected = new List<MemoryBasicInformation>();
            ulong address = 16;
            while (address <= (ulong)maximum)
            {
                var region = Region(address, (ulong)random.Next(1, 100));
                expected.Add(region);
                address += region.RegionSize;
            }
            int index = 0;
            provider = new RegionProvider(query =>
            {
                var region = expected[index++];
                Assert(query == (long)region.BaseAddress, "Query the next region's first byte.");
                return region;
            });
            Assert(new WindowsMemoryRegionEnumerator(provider, new SystemProvider(16, maximum)).EnumerateMemoryRegions()
                .SequenceEqual(expected), "Visit every region exactly once.");
        }
    }

    private static void TestInvalidResults()
    {
        foreach (var region in new[] { Region(16, 0), Region(17, 1), Region(0, 16), Region(16, ulong.MaxValue), Region((ulong)long.MaxValue + 1, 1) })
        {
            var provider = new RegionProvider(_ => region);
            using var enumerator = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(16, 64)).EnumerateMemoryRegions().GetEnumerator();
            Expect<InvalidOperationException>(() => enumerator.MoveNext());
            Assert(provider.Queries.Count == 1, "Reject malformed data before yielding or querying again.");
        }
        foreach (var bounds in new[] { (-1L, 64L), (64L, 16L) })
        {
            var provider = new RegionProvider(_ => Region(16, 16));
            Expect<InvalidOperationException>(() => new WindowsMemoryRegionEnumerator(provider, new SystemProvider(bounds.Item1, bounds.Item2))
                .EnumerateMemoryRegions().ToArray());
            Assert(provider.Queries.Count == 0, "Reject invalid bounds before querying.");
        }
        foreach (int code in new[] { 5, 6, 87 })
        {
            var failure = new PinvokeException("VirtualQueryEx", code);
            var provider = new RegionProvider(address => address == 16 ? Region(16, 16) : throw failure);
            using var enumerator = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(16, 64)).EnumerateMemoryRegions().GetEnumerator();
            Assert(enumerator.MoveNext(), "A query can fail after earlier successful regions.");
            Assert(ReferenceEquals(Expect<PinvokeException>(() => enumerator.MoveNext()), failure), "Query errors, including 87, propagate unchanged.");
        }
    }

    private static void TestCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var system = new SystemProvider(16, 64);
        var provider = new RegionProvider(_ => Region(16, 16));
        Expect<OperationCanceledException>(() => new WindowsMemoryRegionEnumerator(provider, system).EnumerateMemoryRegions(cancellation.Token).ToArray());
        Assert(system.Queries == 0 && provider.Queries.Count == 0, "Pre-cancellation prevents all queries.");
        using var duringSystemQuery = new CancellationTokenSource();
        system = new SystemProvider(16, 64) { OnQuery = () => duringSystemQuery.Cancel() };
        Expect<OperationCanceledException>(() => new WindowsMemoryRegionEnumerator(provider, system).EnumerateMemoryRegions(duringSystemQuery.Token).ToArray());
        Assert(provider.Queries.Count == 0, "Cancellation after system lookup prevents region queries.");
        using var duringRegionQuery = new CancellationTokenSource();
        provider = new RegionProvider(_ => { duringRegionQuery.Cancel(); return Region(16, 16); });
        using var canceledQuery = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(16, 64)).EnumerateMemoryRegions(duringRegionQuery.Token).GetEnumerator();
        Expect<OperationCanceledException>(() => canceledQuery.MoveNext());
        Assert(provider.Queries.Count == 1, "Cancellation during a query prevents yielding its result.");
        using var betweenQueries = new CancellationTokenSource();
        provider = new RegionProvider(address => Region((ulong)address, 16));
        using var paused = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(16, 64)).EnumerateMemoryRegions(betweenQueries.Token).GetEnumerator();
        Assert(paused.MoveNext(), "Yield the first region.");
        betweenQueries.Cancel();
        Expect<OperationCanceledException>(() => paused.MoveNext());
        Assert(provider.Queries.Count == 1, "Cancellation after a yield prevents another query.");
    }

    private static void TestCallerTokenPropagation()
    {
        using var cancellation = new CancellationTokenSource();
        var probe = new EnumerationProbe();
        new WindowsScanner(new UnusedReader(), probe, _ => true).Scan(new UnalignedPatternMatcher(), new byte?[] { 1 }, new ScanOptions(), cancellation.Token);
        Assert(probe.Token == cancellation.Token, "Scanner forwards its token to enumeration.");
        probe = new EnumerationProbe();
        new WindowsNearbyAllocationCandidateProvider(probe, new SystemProvider(16, 64))
            .EnumerateCandidates(32, 1, 16, cancellation.Token).ToArray();
        Assert(probe.Token == cancellation.Token, "Allocation selection forwards its token to enumeration.");
    }

    private static void TestNativeQueries()
    {
        using var process = Process.GetCurrentProcess();
        var handler = new WindowsProcessHandler(process);
        var provider = new WindowsMemoryRegionInformationProvider(handler);
        Expect<ArgumentOutOfRangeException>(() => provider.GetRegionInformation(-1));
        var allocator = new WindowsMemoryAllocator(handler);
        var deallocator = new WindowsMemoryDeallocator(handler);
        long address = allocator.Allocate(null, 4096);
        try
        {
            var region = provider.GetRegionInformation(address + 1);
            Assert(region.BaseAddress <= (ulong)address + 1 && region.RegionSize > 0, "Native query returns complete region metadata.");
            var result = new WindowsMemoryRegionEnumerator(provider, new SystemProvider(address + 1, address + 4095))
                .EnumerateMemoryRegions().Single();
            Assert(result.BaseAddress == (ulong)address && result.RegionSize >= 4096, "Enumerate an unaligned bounded native range.");
        }
        finally { deallocator.Deallocate(address); }
        Console.WriteLine("Native region-query test passed in the test process; allocation released.");
    }

    private static MemoryBasicInformation Region(ulong address, ulong size) => new() { BaseAddress = address, RegionSize = size };
    private static void Assert(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
    private static T Expect<T>(Action action) where T : Exception
    {
        assertions++;
        try { action(); } catch (T exception) { return exception; }
        throw new Exception($"Expected {typeof(T).Name}.");
    }
}

internal sealed class RegionProvider : IMemoryRegionInformationProvider<MemoryBasicInformation>
{
    private readonly Func<long, MemoryBasicInformation> query;
    public RegionProvider(Func<long, MemoryBasicInformation> query) { this.query = query; }
    public List<long> Queries { get; } = new();
    public MemoryBasicInformation GetRegionInformation(long address) { Queries.Add(address); return query(address); }
}

internal sealed class SystemProvider : IWindowsSystemInformationProvider
{
    private readonly long minimum;
    private readonly long maximum;
    public SystemProvider(long minimum, long maximum) { this.minimum = minimum; this.maximum = maximum; }
    public int Queries { get; private set; }
    public Action? OnQuery { get; init; }
    public SystemInformation GetSystemInformation()
    {
        Queries++;
        OnQuery?.Invoke();
        return new SystemInformation { MinimumApplicationAddress = new IntPtr(minimum), MaximumApplicationAddress = new IntPtr(maximum), PageSize = 4, AllocationGranularity = 16 };
    }
}

internal sealed class EnumerationProbe : IMemoryRegionEnumerator<MemoryBasicInformation>
{
    public CancellationToken Token { get; private set; }
    public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions(CancellationToken cancellationToken = default)
    { Token = cancellationToken; return Array.Empty<MemoryBasicInformation>(); }
}

internal sealed class UnusedReader : IMemoryRangeReader
{
    public IEnumerable<MemoryReadResult> ReadRange(long address, ulong lengthInBytes, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("There are no regions to read.");
}

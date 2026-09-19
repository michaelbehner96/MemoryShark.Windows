using System.Diagnostics;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Allocation;
using MemoryShark.Memory.Regions;
using MemoryShark.Windows.Memory.Allocation;
using MemoryShark.Windows.Memory.Regions;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Processes;

namespace NearbyAllocation.Tests
{
    internal static class Program
    {
        private static int assertionCount;

        private static void Main(string[] arguments)
        {
            TestCandidateBoundaries();
            TestAgainstBruteForceSelection();
            TestAllocationFailuresAndOwnership();
            TestValidationAndCancellation();
            TestRegionEnumeratorUsesInjectedSystemInformation();
            if (arguments.Contains("--native")) TestNativeAllocation();
            Console.WriteLine($"Passed {assertionCount} nearby-allocation assertions.");
        }

        private static void TestCandidateBoundaries()
        {
            var regions = new TestRegionEnumerator(FreeRegion(16, 240));
            var selector = CreateSelector(regions);
            AssertSequence(selector.EnumerateCandidates(128, 1, 32), 128, 112, 144, 96);
            Assert(regions.EnumerationCount == 1, "The memory map must be enumerated once.");
            AssertSequence(selector.EnumerateCandidates(128, 17, 16), 112);
            AssertSequence(selector.EnumerateCandidates(128, 1, 0));
            AssertSequence(selector.EnumerateCandidates(0, 1, 35), 16, 32);
            AssertSequence(CreateSelector(new TestRegionEnumerator(FreeRegion(17, 14)))
                .EnumerateCandidates(24, 1, 100));

            var highSystemInformation = new TestSystemInformationProvider(1, 16, 16, long.MaxValue);
            var hugeRegions = new TestRegionEnumerator(FreeRegion(16, ulong.MaxValue));
            var highSelector = new WindowsNearbyAllocationCandidateProvider(hugeRegions, highSystemInformation);
            long highestAlignedAddress = long.MaxValue - 15;
            AssertSequence(highSelector.EnumerateCandidates(long.MaxValue, 1, 64).Take(3),
                highestAlignedAddress, highestAlignedAddress - 16, highestAlignedAddress - 32);
            AssertSequence(highSelector.EnumerateCandidates(16, 1, long.MaxValue).Take(3), 16, 32, 48);

            var normalSystemInformation = new TestSystemInformationProvider(4096, 65536, 65536, long.MaxValue);
            var largeSizeSelector = new WindowsNearbyAllocationCandidateProvider(hugeRegions, normalSystemInformation);
            AssertSequence(largeSizeSelector.EnumerateCandidates(65536, uint.MaxValue, long.MaxValue).Take(1), 65536);
            AssertSequence(CreateSelector(new TestRegionEnumerator(new MemoryBasicInformation
                { BaseAddress = 16, RegionSize = 200, State = MemoryState.Commit }))
                .EnumerateCandidates(128, 1, 100));
        }

        private static void TestAgainstBruteForceSelection()
        {
            var random = new Random(42);
            for (int iteration = 0; iteration < 500; iteration++)
            {
                var memoryRegions = new List<MemoryBasicInformation>();
                ulong regionBase = 0;
                while (regionBase < 4096)
                {
                    ulong regionSize = (ulong)random.Next(1, 150);
                    memoryRegions.Add(new MemoryBasicInformation
                    {
                        BaseAddress = regionBase, RegionSize = regionSize,
                        State = random.Next(3) == 0 ? MemoryState.Commit : MemoryState.Free
                    });
                    regionBase += regionSize;
                }
                long targetAddress = random.Next(0, 4300);
                uint requestedSize = (uint)random.Next(1, 100);
                long maximumDistance = random.Next(0, 4500);
                long roundedSize = ((requestedSize + 3) / 4) * 4;
                var expectedCandidates = new List<long>();

                // Exhaustive reference: check every aligned address independently.
                for (long address = 16; address <= 4095; address += 16)
                {
                    long lastByte = address + roundedSize - 1;
                    bool insideWindow = address >= Math.Max(16, targetAddress - maximumDistance)
                        && lastByte <= Math.Min(4095, targetAddress + maximumDistance);
                    bool insideFreeRegion = memoryRegions.Any(region => region.State == MemoryState.Free
                        && address >= (long)region.BaseAddress
                        && lastByte < (long)(region.BaseAddress + region.RegionSize));
                    if (insideWindow && insideFreeRegion) expectedCandidates.Add(address);
                }
                var regionEnumerator = new TestRegionEnumerator(memoryRegions.ToArray());
                long[] actualCandidates = CreateSelector(regionEnumerator)
                    .EnumerateCandidates(targetAddress, requestedSize, maximumDistance).ToArray();
                long[] expectedOrder = expectedCandidates.OrderBy(address => Math.Abs(address - targetAddress))
                    .ThenBy(address => address).ToArray();
                Assert(actualCandidates.SequenceEqual(expectedOrder), $"Brute-force comparison {iteration} failed.");
                Assert(regionEnumerator.EnumerationCount <= 1, "Repeated memory-map enumeration.");
            }
        }

        private static void TestAllocationFailuresAndOwnership()
        {
            var selector = CreateSelector(new TestRegionEnumerator(FreeRegion(16, 240)));
            var allocator = new TestAllocator((address, attempt) =>
            {
                if (attempt == 1) throw new PinvokeException("VirtualAllocEx", 487);
                return address;
            });
            var deallocator = new TestDeallocator();
            var nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, deallocator);
            Assert(nearbyAllocator.AllocateNear(128, 1, 32) == 112, "Must retry inside the same region.");
            Assert(allocator.Attempts.SequenceEqual(new long[] { 128, 112 }), "Incorrect retry order.");
            Assert(deallocator.ReleasedAddresses.Count == 0, "Successful allocations belong to caller.");

            var deniedException = new PinvokeException("VirtualAllocEx", 5);
            allocator = new TestAllocator((address, attempt) => throw deniedException);
            nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, deallocator);
            Assert(ReferenceEquals(Expect<PinvokeException>(() => nearbyAllocator.AllocateNear(128, 1, 32)),
                deniedException), "Access denied must propagate unchanged.");
            Assert(allocator.Attempts.Count == 1, "Access denied must not trigger more attempts.");

            allocator = new TestAllocator((address, attempt) => throw new PinvokeException("VirtualAllocEx", 487));
            nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, deallocator);
            var exhaustedException = Expect<InvalidOperationException>(() => nearbyAllocator.AllocateNear(128, 1, 32));
            Assert(allocator.Attempts.Count == 4, "Must try all candidates before reporting exhaustion.");
            Assert(exhaustedException.InnerException is PinvokeException, "Preserve the last conflict.");

            allocator = new TestAllocator((address, attempt) => address + 16);
            nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, deallocator);
            Expect<InvalidOperationException>(() => nearbyAllocator.AllocateNear(128, 1, 32));
            Assert(deallocator.ReleasedAddresses.SequenceEqual(new long[] { 144 }), "Release unexpected allocation.");

            allocator = new TestAllocator((address, attempt) => address);
            nearbyAllocator = new WindowsNearbyMemoryAllocator(CreateSelector(new TestRegionEnumerator()), allocator, deallocator);
            Expect<InvalidOperationException>(() => nearbyAllocator.AllocateNear(128, 1, 32));
            Assert(allocator.Attempts.Count == 0, "Do not fall back to an arbitrary allocation.");
        }

        private static void TestValidationAndCancellation()
        {
            var selector = CreateSelector(new TestRegionEnumerator(FreeRegion(16, 240)));
            Expect<ArgumentOutOfRangeException>(() => selector.EnumerateCandidates(-1, 1, 16));
            Expect<ArgumentOutOfRangeException>(() => selector.EnumerateCandidates(16, 0, 16));
            Expect<ArgumentOutOfRangeException>(() => selector.EnumerateCandidates(16, 1, -1));
            var badSystemSelector = new WindowsNearbyAllocationCandidateProvider(
                new TestRegionEnumerator(), new TestSystemInformationProvider(0, 16, 16, 4095));
            Expect<InvalidOperationException>(() => badSystemSelector.EnumerateCandidates(128, 1, 16).ToArray());
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            Expect<OperationCanceledException>(() => selector.EnumerateCandidates(128, 1, 32, cancellation.Token).ToArray());

            using var retryCancellation = new CancellationTokenSource();
            var allocator = new TestAllocator((address, attempt) =>
            {
                retryCancellation.Cancel();
                throw new PinvokeException("VirtualAllocEx", 487);
            });
            var nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, new TestDeallocator());
            Expect<OperationCanceledException>(() => nearbyAllocator.AllocateNear(128, 1, 32, retryCancellation.Token));
            Assert(allocator.Attempts.Count == 1, "Cancellation must prevent further attempts.");
            using var successCancellation = new CancellationTokenSource();
            allocator = new TestAllocator((address, attempt) => { successCancellation.Cancel(); return address; });
            nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, new TestDeallocator());
            Assert(nearbyAllocator.AllocateNear(128, 1, 32, successCancellation.Token) == 128,
                "Concurrent cancellation must not hide an allocation that succeeded.");
        }

        private static void TestRegionEnumeratorUsesInjectedSystemInformation()
        {
            var systemInformationProvider = new TestSystemInformationProvider(4, 16, 16, 64);
            var memoryRegionAnalyzer = new TestRegionAnalyzer();
            var memoryRegionEnumerator = new WindowsMemoryRegionEnumerator(
                memoryRegionAnalyzer, systemInformationProvider);

            MemoryBasicInformation[] regions = memoryRegionEnumerator.EnumerateMemoryRegions().ToArray();
            Assert(systemInformationProvider.QueryCount == 1, "Query injected system information once per enumeration.");
            Assert(memoryRegionAnalyzer.QueriedAddresses.SequenceEqual(new long[] { 16, 32, 48 }),
                "Region queries must follow the injected address bounds.");
            Assert(regions.Select(region => region.BaseAddress).SequenceEqual(new ulong[] { 16, 32, 48 }),
                "Enumeration must return the injected analyzer's regions.");
            Expect<ArgumentNullException>(() => new WindowsMemoryRegionEnumerator(null!, systemInformationProvider));
            Expect<ArgumentNullException>(() => new WindowsMemoryRegionEnumerator(memoryRegionAnalyzer, null!));
            Expect<ArgumentNullException>(() => new WindowsMemoryRegionEnumerator(null!));
        }

        private static void TestNativeAllocation()
        {
            using Process process = Process.GetCurrentProcess();
            var processHandler = new WindowsProcessHandler(process);
            var allocator = new WindowsMemoryAllocator(processHandler);
            var deallocator = new WindowsMemoryDeallocator(processHandler);
            var analyzer = new WindowsMemoryRegionAnalyzer(processHandler);
            var systemInformationProvider = new WindowsSystemInformationProvider();
            var selector = new WindowsNearbyAllocationCandidateProvider(
                new WindowsMemoryRegionEnumerator(analyzer, systemInformationProvider), systemInformationProvider);
            var nearbyAllocator = new WindowsNearbyMemoryAllocator(selector, allocator, deallocator);
            long anchorAddress = allocator.Allocate(null, 4096);
            try
            {
                long allocatedAddress = nearbyAllocator.AllocateNear(anchorAddress, 4097, 16 * 1024 * 1024);
                try
                {
                    var systemInformation = systemInformationProvider.GetSystemInformation();
                    Assert(allocatedAddress % systemInformation.AllocationGranularity == 0, "Native alignment.");
                    long roundedSize = ((4097L + systemInformation.PageSize - 1) / systemInformation.PageSize)
                        * systemInformation.PageSize;
                    Assert(allocatedAddress >= anchorAddress - 16 * 1024 * 1024
                        && allocatedAddress + roundedSize - 1 <= anchorAddress + 16 * 1024 * 1024, "Native range.");
                    Assert(analyzer.Analyze(allocatedAddress).State == MemoryState.Commit, "Native allocation committed.");
                }
                finally { deallocator.Deallocate(allocatedAddress); }
            }
            finally { deallocator.Deallocate(anchorAddress); }
            Console.WriteLine("Native smoke test passed against the test process only; allocations released.");
        }

        private static WindowsNearbyAllocationCandidateProvider CreateSelector(TestRegionEnumerator regions)
        {
            return new WindowsNearbyAllocationCandidateProvider(regions,
                new TestSystemInformationProvider(4, 16, 16, 4095));
        }
        private static MemoryBasicInformation FreeRegion(ulong address, ulong size)
        {
            return new MemoryBasicInformation { BaseAddress = address, RegionSize = size, State = MemoryState.Free };
        }
        private static void AssertSequence(IEnumerable<long> actual, params long[] expected)
        {
            Assert(actual.SequenceEqual(expected), "Candidate sequence mismatch.");
        }
        private static void Assert(bool condition, string message)
        {
            assertionCount++;
            if (!condition) throw new Exception(message);
        }
        private static TException Expect<TException>(Action action) where TException : Exception
        {
            assertionCount++;
            try { action(); }
            catch (TException exception) { return exception; }
            throw new Exception($"Expected {typeof(TException).Name}.");
        }
    }

    internal sealed class TestRegionEnumerator : IMemoryRegionEnumerator<MemoryBasicInformation>
    {
        private readonly MemoryBasicInformation[] regions;
        public int EnumerationCount { get; private set; }
        public TestRegionEnumerator(params MemoryBasicInformation[] regions) { this.regions = regions; }
        public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions()
        {
            EnumerationCount++;
            return regions;
        }
    }
    internal sealed class TestSystemInformationProvider : IWindowsSystemInformationProvider
    {
        private readonly SystemInformation information;
        public int QueryCount { get; private set; }
        public TestSystemInformationProvider(uint pageSize, uint granularity, long minimumAddress, long maximumAddress)
        {
            information = new SystemInformation
            {
                PageSize = pageSize, AllocationGranularity = granularity,
                MinimumApplicationAddress = new IntPtr(minimumAddress), MaximumApplicationAddress = new IntPtr(maximumAddress)
            };
        }
        public SystemInformation GetSystemInformation()
        {
            QueryCount++;
            return information;
        }
    }
    internal sealed class TestRegionAnalyzer : IMemoryRegionAnalyzer<MemoryBasicInformation>
    {
        public List<long> QueriedAddresses { get; } = new();

        public MemoryBasicInformation Analyze(long address)
        {
            QueriedAddresses.Add(address);
            return new MemoryBasicInformation
            {
                BaseAddress = (ulong)address,
                RegionSize = 16,
                State = MemoryState.Free
            };
        }
    }
    internal sealed class TestAllocator : IMemoryAllocator
    {
        private readonly Func<long, int, long> allocate;
        public List<long> Attempts { get; } = new();
        public TestAllocator(Func<long, int, long> allocate) { this.allocate = allocate; }
        public long Allocate(long? baseAddress, uint sizeInBytes)
        {
            if (!baseAddress.HasValue) throw new Exception("Unexpected unconstrained allocation.");
            Attempts.Add(baseAddress.Value);
            return allocate(baseAddress.Value, Attempts.Count);
        }
    }
    internal sealed class TestDeallocator : IMemoryDeallocator
    {
        public List<long> ReleasedAddresses { get; } = new();
        public void Deallocate(long baseAddress) { ReleasedAddresses.Add(baseAddress); }
    }
}

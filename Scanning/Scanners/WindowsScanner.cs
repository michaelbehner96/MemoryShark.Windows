using MemoryShark.Memory;
using MemoryShark.Memory.Regions;
using MemoryShark.Scanning.Algorithms;
using MemoryShark.Scanning.Scanners;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Scanning.Scanners;

public class WindowsScanner : IScanner
{
    private readonly IMemoryIO memoryIO;
    private readonly IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator;

    public WindowsScanner(IMemoryIO memoryIO, IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator,
        Predicate<MemoryBasicInformation> memoryRegionFilter)
    {
        this.memoryIO = memoryIO ?? throw new ArgumentNullException(nameof(memoryIO));
        this.memoryRegionEnumerator =
            memoryRegionEnumerator ?? throw new ArgumentNullException(nameof(memoryRegionEnumerator));
        MemoryRegionFilter = memoryRegionFilter ?? throw new ArgumentNullException(nameof(memoryRegionFilter));
    }

    public Predicate<MemoryBasicInformation> MemoryRegionFilter { get; set; }

    public long[] Scan(IScanAlgorithm algorithm, byte?[] signature)
    {
        var matchedAddresses = new List<long>();

        foreach (var region in memoryRegionEnumerator.EnumerateMemoryRegions()
                     .Where(memRegion => MemoryRegionFilter(memRegion)))
        {
            var bytesRead = memoryIO.ReadMemory((long)region.BaseAddress, region.RegionSize);

            var matches = algorithm.FindMatches(bytesRead, signature);

            foreach (var index in matches) matchedAddresses.Add((long)region.BaseAddress + index);
        }

        return matchedAddresses.ToArray();
    }
}
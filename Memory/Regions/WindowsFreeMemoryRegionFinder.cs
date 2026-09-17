using MemoryShark.Memory.Regions;
using MemoryShark.Utility;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Memory.Regions
{
    public class WindowsFreeMemoryRegionFinder : IFreeMemoryRegionFinder<MemoryBasicInformation>
    {
        private const ulong MaximumAllocationRange = 0x80000000;
        private readonly IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator;

        public WindowsFreeMemoryRegionFinder(IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator)
        {
            this.memoryRegionEnumerator = memoryRegionEnumerator;
        }

        public MemoryBasicInformation FindFreeRegion(long? nearThisAddress)
        {
            if (nearThisAddress is < 0)
                throw new ArgumentOutOfRangeException(nameof(nearThisAddress), "Address cannot be negative.");

            ulong? targetAddress = nearThisAddress.HasValue ? (ulong)nearThisAddress.Value : null;
            var minAddress = targetAddress is > MaximumAllocationRange
                ? targetAddress.Value - MaximumAllocationRange
                : ulong.MinValue;
            var maxAddress = targetAddress is <= ulong.MaxValue - MaximumAllocationRange
                ? targetAddress.Value + MaximumAllocationRange
                : ulong.MaxValue;

            var regions = memoryRegionEnumerator
                .EnumerateMemoryRegions()
                .Where(memRegion =>
                    memRegion.BaseAddress > minAddress && // We are above minimum distance
                    memRegion.BaseAddress < maxAddress && // we are below maximum distance
                    memRegion.State == MemoryState.Free);// Region is 'free'

            if (!regions.Any())
                throw new Exception();

            return targetAddress.HasValue ?
                regions.OrderBy(memRegion => memRegion.BaseAddress >= targetAddress.Value
                    ? memRegion.BaseAddress - targetAddress.Value
                    : targetAddress.Value - memRegion.BaseAddress).First() :
                regions.First();
        }
    }
}

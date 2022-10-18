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
            var minAddress = nearThisAddress.HasValue ? (ulong)nearThisAddress.Value - MaximumAllocationRange : ulong.MinValue;
            var maxAddress = nearThisAddress.HasValue ? (ulong)nearThisAddress.Value + MaximumAllocationRange : ulong.MaxValue;

            var regions = memoryRegionEnumerator
                .EnumerateMemoryRegions()
                .Where(memRegion =>
                    memRegion.BaseAddress > minAddress && // We are above minimum distance
                    memRegion.BaseAddress < maxAddress && // we are below maximum distance
                    memRegion.State == MemoryState.Free);// Region is 'free'

            if (!regions.Any())
                throw new Exception();

            return nearThisAddress.HasValue ?
                regions.OrderBy(mr => (int)Math.Abs((decimal)(mr.BaseAddress - (ulong)nearThisAddress.Value))).First() :
                regions.First();
        }
    }
}

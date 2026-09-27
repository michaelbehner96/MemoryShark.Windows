using MemoryShark.Memory.Regions;
using MemoryShark.Providers;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Providers;

namespace MemoryShark.Windows.Memory.Regions;

public class WindowsMemoryRegionEnumerator : IMemoryRegionEnumerator<MemoryBasicInformation>
{
    private readonly IMemoryRegionInformationProvider<MemoryBasicInformation> memoryRegionInformationProvider;
    private readonly IWindowsSystemInformationProvider systemInformationProvider;

    public WindowsMemoryRegionEnumerator(IMemoryRegionInformationProvider<MemoryBasicInformation> memoryRegionInformationProvider, IWindowsSystemInformationProvider systemInformationProvider)
    {
        this.memoryRegionInformationProvider = memoryRegionInformationProvider ?? throw new ArgumentNullException(nameof(memoryRegionInformationProvider));
        this.systemInformationProvider = systemInformationProvider ?? throw new ArgumentNullException(nameof(systemInformationProvider));
    }

    public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var systemInformation = systemInformationProvider.GetSystemInformation();
        cancellationToken.ThrowIfCancellationRequested();

        var minimumAddress = systemInformation.MinimumApplicationAddress.ToInt64();
        var maximumAddress = systemInformation.MaximumApplicationAddress.ToInt64();

        if (minimumAddress < 0 || maximumAddress < minimumAddress)
            throw new InvalidOperationException("Invalid application address bounds.");

        var currentAddress = minimumAddress;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var memoryRegion = memoryRegionInformationProvider.GetRegionInformation(currentAddress);
            cancellationToken.ThrowIfCancellationRequested();

            if (memoryRegion.RegionSize == 0)
                throw new InvalidOperationException($"The region query at 0x{currentAddress:X} returned an empty region.");
            
            if (memoryRegion.BaseAddress > (ulong)currentAddress)
                throw new InvalidOperationException($"The region query at 0x{currentAddress:X} returned a region starting after the queried address.");

            // Validate an inclusive endpoint without overflowing or narrowing an unsigned size.
            var bytesAfterRegionBase = memoryRegion.RegionSize - 1;

            if (bytesAfterRegionBase > long.MaxValue - memoryRegion.BaseAddress)
                throw new InvalidOperationException($"The region query at 0x{currentAddress:X} returned a range outside the supported address space.");
            
            var lastRegionAddress = checked(memoryRegion.BaseAddress + bytesAfterRegionBase);

            if (lastRegionAddress < (ulong)currentAddress)
                throw new InvalidOperationException($"The region query at 0x{currentAddress:X} returned a region ending before the queried address.");

            yield return memoryRegion;

            cancellationToken.ThrowIfCancellationRequested();

            // The system limit is inclusive. Do not form a next address beyond long.MaxValue.
            if (lastRegionAddress >= (ulong)maximumAddress) yield break;
            currentAddress = checked((long)lastRegionAddress + 1);
        }
    }
}
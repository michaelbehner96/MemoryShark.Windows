using MemoryShark.Memory.Allocation;
using MemoryShark.Memory.Regions;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Providers;

namespace MemoryShark.Windows.Memory.Allocation;

/// <summary>
///     Selects addresses from one enumeration of the free memory map.
///     Allocation attempts are the responsibility of WindowsNearbyMemoryAllocator.
/// </summary>
public class WindowsNearbyAllocationCandidateProvider : INearbyAllocationCandidateProvider
{
    private readonly IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator;
    private readonly IWindowsSystemInformationProvider systemInformationProvider;

    public WindowsNearbyAllocationCandidateProvider(IMemoryRegionEnumerator<MemoryBasicInformation> memoryRegionEnumerator, IWindowsSystemInformationProvider systemInformationProvider)
    {
        this.memoryRegionEnumerator = memoryRegionEnumerator ?? throw new ArgumentNullException(nameof(memoryRegionEnumerator));
        this.systemInformationProvider = systemInformationProvider ?? throw new ArgumentNullException(nameof(systemInformationProvider));
    }

    public IEnumerable<long> EnumerateCandidates(long targetAddress, uint sizeInBytes, long maximumDistanceInBytes, CancellationToken cancellationToken = default)
    {
        if (targetAddress < 0)
            throw new ArgumentOutOfRangeException(nameof(targetAddress));
        if (sizeInBytes == 0)
            throw new ArgumentOutOfRangeException(nameof(sizeInBytes));
        if (maximumDistanceInBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(maximumDistanceInBytes));

        return EnumerateValidatedCandidates(targetAddress, sizeInBytes, maximumDistanceInBytes, cancellationToken);
    }

    private IEnumerable<long> EnumerateValidatedCandidates(long targetAddress, uint sizeInBytes, long maximumDistanceInBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var systemInformation = systemInformationProvider.GetSystemInformation();
        ValidateSystemInformation(systemInformation);

        ulong allocationGranularity = systemInformation.AllocationGranularity;
        var roundedAllocationSize = AlignUp(sizeInBytes, systemInformation.PageSize);
        var unsignedTargetAddress = (ulong)targetAddress;
        var maximumDistance = (ulong)maximumDistanceInBytes;

        var minimumWindowAddress = unsignedTargetAddress >= maximumDistance ? unsignedTargetAddress - maximumDistance : 0;
        // Both operands originate from nonnegative longs, so their sum fits in ulong.
        var maximumWindowAddress = Math.Min(unsignedTargetAddress + maximumDistance, long.MaxValue);
        minimumWindowAddress = Math.Max(minimumWindowAddress, (ulong)systemInformation.MinimumApplicationAddress.ToInt64());
        maximumWindowAddress = Math.Min(maximumWindowAddress, (ulong)systemInformation.MaximumApplicationAddress.ToInt64());

        if (minimumWindowAddress > maximumWindowAddress)
            yield break;

        // At most two cursors per region: one moving downward, one upward.
        // This avoids materializing every granularity-sized candidate in a large region.
        var candidateQueue = new PriorityQueue<CandidateCursor, (ulong Distance, ulong Address)>();

        foreach (var memoryRegion in memoryRegionEnumerator.EnumerateMemoryRegions())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (memoryRegion.State != MemoryState.Free || memoryRegion.RegionSize == 0)
                continue;
            if (memoryRegion.BaseAddress > maximumWindowAddress)
                continue;

            // Inclusive endpoints make full-allocation containment explicit.
            var bytesAfterRegionBase = memoryRegion.RegionSize - 1;
            var lastRegionAddress = bytesAfterRegionBase > ulong.MaxValue - memoryRegion.BaseAddress ? ulong.MaxValue : memoryRegion.BaseAddress + bytesAfterRegionBase;
            var firstUsableAddress = Math.Max(memoryRegion.BaseAddress, minimumWindowAddress);
            var lastUsableAddress = Math.Min(lastRegionAddress, maximumWindowAddress);

            if (firstUsableAddress > lastUsableAddress)
                continue;
            if (roundedAllocationSize - 1 > lastUsableAddress - firstUsableAddress)
                continue;

            var firstCandidateAddress = AlignUp(firstUsableAddress, allocationGranularity);
            // Address zero means 'choose anywhere' to VirtualAllocEx, not a fixed address.
            firstCandidateAddress = Math.Max(firstCandidateAddress, allocationGranularity);
            var lastCandidateAddress = AlignDown(lastUsableAddress - (roundedAllocationSize - 1), allocationGranularity);

            if (firstCandidateAddress > lastCandidateAddress)
                continue;

            var alignedTargetAddress = AlignDown(unsignedTargetAddress, allocationGranularity);
            var lowerCandidateAddress = Math.Min(alignedTargetAddress, lastCandidateAddress);
            if (lowerCandidateAddress >= firstCandidateAddress)
                EnqueueCandidate(candidateQueue, new CandidateCursor(lowerCandidateAddress, firstCandidateAddress, false), unsignedTargetAddress);

            var upperCandidateAddress = Math.Max(firstCandidateAddress, alignedTargetAddress + allocationGranularity);
            if (upperCandidateAddress <= lastCandidateAddress)
                EnqueueCandidate(candidateQueue, new CandidateCursor(upperCandidateAddress, lastCandidateAddress, true), unsignedTargetAddress);
        }

        while (candidateQueue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = candidateQueue.Dequeue();

            yield return checked((long)candidate.Address);

            if (candidate.Address == candidate.FinalAddress)
                continue;

            var nextAddress = candidate.IsAscending ? candidate.Address + allocationGranularity : candidate.Address - allocationGranularity;
            EnqueueCandidate(candidateQueue, new CandidateCursor(nextAddress, candidate.FinalAddress, candidate.IsAscending), unsignedTargetAddress);
        }
    }

    private static void ValidateSystemInformation(SystemInformation systemInformation)
    {
        if (systemInformation.PageSize == 0 || systemInformation.AllocationGranularity == 0)
            throw new InvalidOperationException("Page size and allocation granularity must be positive.");
        if (systemInformation.AllocationGranularity % systemInformation.PageSize != 0)
            throw new InvalidOperationException("Allocation granularity must be a multiple of page size.");
        if (systemInformation.MinimumApplicationAddress.ToInt64() < 0 || systemInformation.MaximumApplicationAddress.ToInt64() < systemInformation.MinimumApplicationAddress.ToInt64())
            throw new InvalidOperationException("Invalid application address bounds.");
    }

    private static ulong AlignDown(ulong address, ulong alignment)
    {
        return address - address % alignment;
    }

    private static ulong AlignUp(ulong address, ulong alignment)
    {
        var remainder = address % alignment;

        return remainder == 0 ? address : checked(address + alignment - remainder);
    }

    private static void EnqueueCandidate(PriorityQueue<CandidateCursor, (ulong Distance, ulong Address)> candidateQueue, CandidateCursor candidate, ulong targetAddress)
    {
        var distance = candidate.Address >= targetAddress ? candidate.Address - targetAddress : targetAddress - candidate.Address;
        candidateQueue.Enqueue(candidate, (distance, candidate.Address));
    }

    private sealed class CandidateCursor
    {
        public ulong Address { get; }
        public ulong FinalAddress { get; }
        public bool IsAscending { get; }

        public CandidateCursor(ulong address, ulong finalAddress, bool isAscending)
        {
            Address = address;
            FinalAddress = finalAddress;
            IsAscending = isAscending;
        }
    }
}
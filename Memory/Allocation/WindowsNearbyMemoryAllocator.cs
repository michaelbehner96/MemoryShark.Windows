using MemoryShark.Exceptions;
using MemoryShark.Memory.Allocation;

namespace MemoryShark.Windows.Memory.Allocation;

/// <summary>
///     Coordinates candidate selection and the existing allocation wrapper.
///     All injected services must describe or operate on the same target process.
/// </summary>
public class WindowsNearbyMemoryAllocator : INearbyMemoryAllocator
{
    private const long ErrorInvalidAddress = 487;
    private readonly INearbyAllocationCandidateProvider candidateProvider;
    private readonly IMemoryAllocator memoryAllocator;
    private readonly IMemoryDeallocator memoryDeallocator;

    public WindowsNearbyMemoryAllocator(INearbyAllocationCandidateProvider candidateProvider,
        IMemoryAllocator memoryAllocator, IMemoryDeallocator memoryDeallocator)
    {
        this.candidateProvider = candidateProvider ?? throw new ArgumentNullException(nameof(candidateProvider));
        this.memoryAllocator = memoryAllocator ?? throw new ArgumentNullException(nameof(memoryAllocator));
        this.memoryDeallocator = memoryDeallocator ?? throw new ArgumentNullException(nameof(memoryDeallocator));
    }

    public long AllocateNear(long targetAddress, uint sizeInBytes, long maximumDistanceInBytes,
        CancellationToken cancellationToken = default)
    {
        if (targetAddress < 0)
            throw new ArgumentOutOfRangeException(nameof(targetAddress));
        if (sizeInBytes == 0)
            throw new ArgumentOutOfRangeException(nameof(sizeInBytes));
        if (maximumDistanceInBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(maximumDistanceInBytes));

        cancellationToken.ThrowIfCancellationRequested();
        PinvokeException? lastAddressConflict = null;
        long attemptedAllocationCount = 0;

        foreach (var candidateAddress in candidateProvider.EnumerateCandidates(
                     targetAddress, sizeInBytes, maximumDistanceInBytes, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            attemptedAllocationCount++;
            long allocatedAddress;
            try
            {
                allocatedAddress = memoryAllocator.Allocate(candidateAddress, sizeInBytes);
            }
            catch (PinvokeException exception) when (exception.ErrorCode == ErrorInvalidAddress)
            {
                // The free-space observation may be stale. Try another aligned location,
                // including another location in the same region. Other errors propagate.
                lastAddressConflict = exception;
                continue;
            }

            if (allocatedAddress == candidateAddress) return allocatedAddress;
            if (allocatedAddress != 0)
                memoryDeallocator.Deallocate(allocatedAddress);
            throw new InvalidOperationException(
                "The allocator did not return the requested candidate address. The unexpected allocation was released when nonzero.");

            // After success, return ownership even if cancellation arrives concurrently.
            // Throwing here would hide a live allocation from the caller.
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException(
            $"Unable to allocate {sizeInBytes} bytes within {maximumDistanceInBytes} bytes of " +
            $"0x{targetAddress:X}. Attempted {attemptedAllocationCount} candidate addresses.",
            lastAddressConflict);
    }
}
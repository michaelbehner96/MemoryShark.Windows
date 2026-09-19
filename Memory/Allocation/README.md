# Nearby memory allocation

`WindowsNearbyMemoryAllocator` composes the existing allocator and deallocator with
`WindowsNearbyAllocationCandidateProvider`. It does not inherit from the existing
allocator or use `WindowsFreeMemoryRegionFinder`. The old finder remains available
for compatibility; new nearby-allocation code should use this service instead.

## Construction

```csharp
var processHandler = new WindowsProcessHandler(process);
var memoryAllocator = new WindowsMemoryAllocator(processHandler);
var memoryDeallocator = new WindowsMemoryDeallocator(processHandler);
var memoryRegionAnalyzer = new WindowsMemoryRegionAnalyzer(processHandler);
var systemInformationProvider = new WindowsSystemInformationProvider();
var memoryRegionEnumerator = new WindowsMemoryRegionEnumerator(
    memoryRegionAnalyzer, systemInformationProvider);

var candidateProvider = new WindowsNearbyAllocationCandidateProvider(
    memoryRegionEnumerator, systemInformationProvider);
var nearbyAllocator = new WindowsNearbyMemoryAllocator(
    candidateProvider, memoryAllocator, memoryDeallocator);

long allocatedAddress = nearbyAllocator.AllocateNear(
    targetAddress, sizeInBytes: 4096, maximumDistanceInBytes: 16 * 1024 * 1024,
    cancellationToken: cancellationToken);
try
{
    // Use the allocation.
}
finally
{
    memoryDeallocator.Deallocate(allocatedAddress);
}
```

All process-related dependencies must use the same process. The system-information
provider retrieves Windows system information independently of allocation or caller
bitness. The native memory-region analyzer requires a 64-bit calling process because
of its existing memory-region interop layout. This change does not add general
cross-bitness support. The region enumerator accepts an injected system-information
provider; its original single-argument constructor remains as a convenience overload.

## Contract and behavior

- Addresses retain the existing nonnegative `long` contract; sizes are positive
  `uint` values. Maximum distance is a nonnegative `long`, supplied explicitly.
- The entire page-rounded allocation fits inside the inclusive target +/- distance
  window, intersected with the system application-address bounds. Zero distance
  usually cannot accommodate a full page. Address zero is never submitted.
- Region overlap, allocation granularity, page rounding, and full allocation size
  determine valid candidates. A region whose base lies outside the window can still
  contribute candidates from inside the region.
- Each request enumerates the region map once. A priority queue merges ascending
  and descending candidate sequences, nearest first, with lower addresses winning
  ties. Memory use scales with the number of regions, not every possible address.
- An address conflict (`ERROR_INVALID_ADDRESS`, 487) advances to the next candidate,
  including candidates in the same region. Access denial, resource exhaustion, and
  other failures propagate immediately. Exhaustion reports the attempt count and
  retains the last address-conflict exception as its inner exception.
- Candidates reflect observations, not an atomic snapshot or reservation. Success
  means the first candidate that actually allocated, not a guarantee of the nearest
  free address at the instant of return. Newly freed space requires a new request.
- Unexpected nonzero allocation results are released and reported as contract
  violations. A successfully returned allocation belongs to the caller. Cancellation
  after a successful native allocation does not discard that ownership.
- Cancellation is checked while enumerating regions/candidates and before attempts.
  It cannot interrupt an individual native call. Run this synchronous operation off
  the UI thread. Very large windows with many conflicts may take substantial time.
- Memory protection remains the responsibility of the injected allocator; the
  existing Windows allocator requests executable/read/write memory.

For relative branches, the caller must calculate reach from the end of the actual
instruction and validate the final encoded displacement. This allocator knows
address windows, not instruction lengths, jump encodings, or trampoline relocation.

## Verification

The dependency-free regression runner uses fake services and a brute-force selector
to test ordering, containment, page rounding, bounds, retry behavior, cancellation,
and ownership. From the repository root:

```text
dotnet run --project Tests/NearbyAllocation/NearbyAllocation.Tests.csproj
dotnet run --project Tests/NearbyAllocation/NearbyAllocation.Tests.csproj -- --native
```

The optional native smoke test allocates only in its own test process and releases
both blocks in `finally` statements. It does not attach to a game.

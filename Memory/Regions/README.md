# Memory-region enumeration

`WindowsMemoryRegionEnumerator` queries the injected region-information provider
from the system's minimum application address through its inclusive maximum.
It yields the provider's original region metadata without clipping it to those
bounds. A returned range may therefore begin before the first query or extend
past the enumeration limit.

Before yielding, it rejects empty regions, ranges that do not contain the queried
address, and endpoints outside the library's nonnegative `long` address space.
Inclusive endpoint arithmetic uses unsigned sizes without narrowing them first.
Traversal advances to the returned range's last byte plus one, and terminates
before that addition if the region already covers the enumeration limit.
Invalid system bounds are rejected before querying regions.

`WindowsMemoryRegionInformationProvider` owns native-query validation: it rejects
negative addresses, requires the existing Windows/64-bit caller support, propagates
native failures, and verifies that VirtualQueryEx returned exactly the expected
structure size before exposing the metadata. Traversal validation belongs to the
enumerator, not to its scanner or allocation consumers.

`EnumerateMemoryRegions(CancellationToken cancellationToken = default)` checks
cancellation before and after system and region queries, and when resuming after
a yield. A running native call cannot be interrupted. The scanner and allocation
candidate provider forward their tokens. Custom enumerator implementations must
update their signatures; callers without a token remain valid.

Query failures never become successful completion, including error 87. System
address bounds do not establish every target process's accessible upper bound;
target-specific architecture support is still a separate concern. Enumeration is
an observation over time, not an atomic snapshot, and query exceptions can occur
after earlier regions have already been yielded.

## Verification

From the Windows project directory:

```text
dotnet run --project Tests/Regions/Regions.Tests.csproj -- --native
dotnet run --project Tests/NearbyAllocation/NearbyAllocation.Tests.csproj -- --native
dotnet run --project Tests/Scanning/Scanning.Tests.csproj -- --native
```

The region tests cover randomized traversal, unaligned starting queries, inclusive
bounds, zero sizes, malformed endpoints, unsigned size handling, cancellation,
error propagation, and caller token forwarding. Native tests query only their own
process and release their test allocations. Unexpected native structure sizes
are guarded in production; the native success path exercises the actual layout,
while truncated native returns are not synthesized by these tests.

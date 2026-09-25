using MemoryShark.Exceptions;
using MemoryShark.Memory;
using MemoryShark.Memory.Reading;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Providers;

namespace MemoryShark.Windows.Memory.Reading;

public sealed class WindowsMemoryRangeReader : IMemoryRangeReader
{
    private readonly int maximumBatchSizeInBytes;
    private readonly IMemoryIO memoryIO;
    private readonly int pageSizeInBytes;
    private readonly MemoryReadFailurePolicy readFailurePolicy;

    public WindowsMemoryRangeReader(IMemoryIO memoryIO, IWindowsSystemInformationProvider systemInformationProvider, int pagesPerRead = 256, MemoryReadFailurePolicy readFailurePolicy = MemoryReadFailurePolicy.SkipUnreadable)
    {
        ArgumentNullException.ThrowIfNull(memoryIO);
        ArgumentNullException.ThrowIfNull(systemInformationProvider);

        if (pagesPerRead <= 0)
            throw new ArgumentOutOfRangeException(nameof(pagesPerRead), "Pages per read must be positive.");

        if (!Enum.IsDefined(typeof(MemoryReadFailurePolicy), readFailurePolicy))
            throw new ArgumentOutOfRangeException(nameof(readFailurePolicy), "Unknown read failure policy.");

        var systemPageSize = systemInformationProvider.GetSystemInformation().PageSize;

        if (systemPageSize is 0 or > int.MaxValue)
            throw new InvalidOperationException($"Invalid system page size (pageSize={systemPageSize}).");

        pageSizeInBytes = (int)systemPageSize;

        maximumBatchSizeInBytes = checked(pageSizeInBytes * pagesPerRead);

        if (maximumBatchSizeInBytes > Array.MaxLength)
            throw new ArgumentOutOfRangeException(nameof(pagesPerRead), "The configured page count exceeds the supported read buffer size.");

        this.memoryIO = memoryIO;
        this.readFailurePolicy = readFailurePolicy;
    }

    public IEnumerable<MemoryReadResult> ReadRange(long address, ulong lengthInBytes, CancellationToken cancellationToken = default)
    {
        if (address < 0)
            throw new ArgumentOutOfRangeException(nameof(address), "The address must be nonnegative.");

        if (lengthInBytes > 0 && lengthInBytes - 1 > (ulong)(long.MaxValue - address))
            throw new ArgumentOutOfRangeException(nameof(lengthInBytes), "The requested range exceeds the supported address range.");

        return ReadValidatedRange(address, lengthInBytes, cancellationToken);
    }

    private IEnumerable<MemoryReadResult> ReadValidatedRange(long address, ulong lengthInBytes, CancellationToken cancellationToken)
    {
        ulong consumedBytes = 0;

        while (consumedBytes < lengthInBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batchAddress = checked(address + (long)consumedBytes);
            // End full batches on page boundaries without reading before the requested start.
            var offsetWithinPage = (int)(batchAddress % pageSizeInBytes);
            var bytesToBatchBoundary = maximumBatchSizeInBytes - offsetWithinPage;
            var batchLength = (int)Math.Min((ulong)bytesToBatchBoundary, lengthInBytes - consumedBytes);
            var batch = ReadBatch(batchAddress, batchLength, cancellationToken);

            if (batch.Data != null)
            {
                yield return batch;
            }
            else
            {
                if (batchLength <= pageSizeInBytes - offsetWithinPage)
                {
                    // This read already fits in one page; do not repeat the same failed attempt.
                    yield return batch;
                }
                else
                {
                    // Failed native buffers are never exposed as successful bytes.
                    // Each intersecting page is attempted once, clipped to this failed range.
                    var recoveredBytes = 0;

                    while (recoveredBytes < batchLength)
                    {
                        var pageAddress = checked(batchAddress + recoveredBytes);
                        var bytesToPageBoundary = pageSizeInBytes - (int)(pageAddress % pageSizeInBytes);
                        var recoveryLength = Math.Min(bytesToPageBoundary, batchLength - recoveredBytes);

                        yield return ReadBatch(pageAddress, recoveryLength, cancellationToken);
                        recoveredBytes += recoveryLength;
                    }
                }
            }

            consumedBytes += (ulong)batchLength;
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private MemoryReadResult ReadBatch(long address, int length, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var data = memoryIO.ReadMemory(address, (ulong)length);

            if (data.Length < length)
                throw new IncompleteMemoryTransferException(nameof(IMemoryIO.ReadMemory), address, (ulong)length, (ulong)data.Length);

            if (data.Length > length)
                throw new InvalidOperationException("The memory reader returned more bytes than requested.");

            cancellationToken.ThrowIfCancellationRequested();

            return new MemoryReadResult(address, length, data, null);
        }
        catch (Exception exception) when (readFailurePolicy == MemoryReadFailurePolicy.SkipUnreadable && IsRecoverable(exception))
        {
            cancellationToken.ThrowIfCancellationRequested();

            return new MemoryReadResult(address, length, null, exception);
        }
    }

    private static bool IsRecoverable(Exception exception)
    {
        if (exception is IncompleteMemoryTransferException)
            return true;

        // Access denial, invalid handles, process exit and unexpected failures must propagate.
        return exception is PinvokeException
        {
            ErrorCode: (long)WindowsErrorCode.PartialCopy or (long)WindowsErrorCode.InvalidAddress or (long)WindowsErrorCode.NoAccess
        };
    }
}
namespace MemoryShark.Windows.Native.Constants
{
    /// <summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex#parameters"/>
    /// </summary>
    [Flags]
    public enum AllocationTypeFlags
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        Physical = 0x400000,
        TopDown = 0x100000
    }
}

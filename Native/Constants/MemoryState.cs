namespace MemoryShark.Windows.Native.Constants
{
    /// <summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information#members"/>
    /// </summary>
    /// <remarks>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/memory/page-state"/>
    /// </remarks>
    public enum MemoryState : uint
    {
        /// <summary>
        /// Indicates committed pages for which physical storage has been allocated, either in memory or in the paging file on disk. 
        /// </summary>
        Commit = 0x1000,
        /// <summary>
        /// Indicates free pages not accessible to the calling process and available to be allocated.
        /// </summary>
        Free = 0x10000,
        /// <summary>
        /// Indicates reserved pages where a range of the process's virtual address space is reserved without any physical storage being allocated. 
        /// </summary>
        Reserve = 0x2000
    }
}

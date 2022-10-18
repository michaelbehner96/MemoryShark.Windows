using System.Runtime.InteropServices;
using MemoryShark.Windows.Native.Constants;

namespace MemoryShark.Windows.Native.Structures
{
    /// <summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information"/>
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct MemoryBasicInformation
    {
        /// <summary>
        /// A pointer to the base address of the region of pages.
        /// </summary>
        [FieldOffset(0)] public ulong BaseAddress;

        /// <summary>
        /// A pointer to the base address of a range of pages allocated by the <c>VirtualAlloc</c> function. 
        /// The page pointed to by the BaseAddress member is contained within this allocation range.
        /// </summary>
        [FieldOffset(8)] public ulong AllocationBase;

        /// <summary>
        /// The <see cref="MemoryProtectionFlags"/> option when the region was initially allocated.
        /// </summary>
        /// <remarks>
        /// This member can be one of the <see cref="MemoryProtectionFlags"/> constants or 0 if the caller does not have access.
        /// </remarks>
        [FieldOffset(16)] public MemoryProtectionFlags AllocationProtect;

        /// <summary>
        /// The size of the region (in bytes), beginning at the <see cref="BaseAddress">BaseAddress</see> in which all pages have identical attributes.
        /// </summary>
        [FieldOffset(24)] public ulong RegionSize;

        /// <summary>
        /// The <see cref="MemoryState"/> of the pages in the region.
        /// </summary>
        [FieldOffset(32)] public MemoryState State;

        /// <summary>
        /// The <see cref="MemoryProtectionFlags"/> of the pages in the region.
        /// </summary>
        [FieldOffset(36)] public MemoryProtectionFlags Protect;

        /// <summary>
        /// The <see cref="MemoryType"/> of pages in the region.
        /// </summary>
        [FieldOffset(40)] public MemoryType Type;
    }
}

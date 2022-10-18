using System.Runtime.InteropServices;
using MemoryShark.Windows.Native.Constants;

namespace MemoryShark.Windows.Native.Structures
{
    /// <summary>
    /// Contains information about the current computer system. 
    /// This includes the architecture and type of the processor, the number of processors in the system, the page size, and other such information.
    /// </summary>
    /// <remarks>
    /// To be populated using <see cref="WindowsPinvoke.GetSystemInfo(ref SystemInformation)"/>
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    public struct SystemInformation
    {
        /// <summary>
        /// The processor architecture of the installed operating system.
        /// </summary>
        public ProcessorArchitecture ProcessorArchitecture;

        /// <summary>
        /// Unused.
        /// </summary>
        public ushort Reserved;

        /// <summary>
        /// The page size and the granularity of page protection and commitment.
        /// </summary>
        /// <remarks>
        /// This is the page size used by <see cref="WindowsPinvoke.VirtualAllocEx(IntPtr, IntPtr, uint, AllocationTypeFlags, MemoryProtectionFlags)">VirtualAllocEx</see>.
        /// </remarks>
        public uint PageSize;

        /// <summary>
        /// A pointer to the lowest memory address accessible to applications and dynamic-link libraries (DLLs).
        /// </summary>
        public IntPtr MinimumApplicationAddress;

        /// <summary>
        /// A pointer to the highest memory address accessible to applications and DLLs.
        /// </summary>
        public IntPtr MaximumApplicationAddress;

        /// <summary>
        /// A mask representing the set of processors configured into the system. Bit 0 is processor 0; bit 31 is processor 31.
        /// </summary>
        public uint ActiveProcessorMask;

        /// <summary>
        /// The number of logical processors in the current group.
        /// </summary>
        public uint NumberOfProcessors;

        /// <summary>
        /// An obsolete member that is retained for compatibility.
        /// </summary>
        public uint ProcessorType;

        /// <summary>
        /// The granularity for the starting address at which virtual memory can be allocated.
        /// </summary>
        public uint AllocationGranularity;

        /// <summary>
        /// The architecture-dependent processor level. It should be used only for display purposes.
        /// </summary>
        public ushort ProcessorLevel;

        /// <summary>
        /// The architecture-dependent processor revision. 
        /// </summary>
        public ushort ProcessorRevision;
    }

    public enum ProcessorArchitecture : ushort
    {
        AMD64 = 0x9,
        ARM = 0x5,
        ARM64 = 12,
        IA64 = 0x6,
        INTEL = 0x0,
        UNKNOWN = 0xFFFF
    }
}

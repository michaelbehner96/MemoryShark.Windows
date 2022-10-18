namespace MemoryShark.Windows.Native.Constants
{
    /// <summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants"/>
    /// </summary>
    [Flags]
    public enum MemoryProtectionFlags
    {
        /// <summary>
        /// Execute access to the committed region of pages. 
        /// </summary>
        /// <remarks>
        /// An attempt to write to the committed region results in an access violation.
        /// </remarks>
        Execute = 0x10,

        /// <summary>
        /// Execute or read-only access to the committed region of pages. 
        /// </summary>
        /// <remarks>
        /// An attempt to write to the committed region results in an access violation.
        /// </remarks>
        ExecuteRead = 0x20,

        /// <summary>
        /// Execute, read-only, or read/write access to the committed region of pages.
        /// </summary>
        ExecuteReadWrite = 0x40,

        /// <summary>
        /// Execute, read-only, or copy-on-write access to a mapped view of a file mapping object. 
        /// </summary>
        /// <remarks>
        /// An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process. 
        /// The private page is marked as <see cref="ExecuteReadWrite"/>, and the change is written to the new page.
        /// </remarks>
        ExecuteWriteCopy = 0x80,

        /// <summary>
        /// All access to the committed region of pages is disabled. 
        /// An attempt to read from, write to, or execute the committed region results in an access violation.
        /// </summary>
        /// <remarks>
        /// An attempt to read from, write to, or execute the committed region results in an access violation.
        /// </remarks>
        NoAccess = 0x01,

        /// <summary>
        /// Read-only access to the committed region of pages. 
        /// </summary>
        /// <remarks>
        /// An attempt to write to the committed region results in an access violation. 
        /// If <c>Data Execution Prevention</c> is enabled, an attempt to execute code in the committed region results in an access violation.
        /// </remarks>
        ReadOnly = 0x02,

        /// <summary>
        /// Read-only or read/write access to the committed region of pages.
        /// </summary>
        /// <remarks>
        /// If <c>Data Execution Prevention</c> is enabled, an attempt to execute code in the committed region results in an access violation.
        /// </remarks>
        ReadWrite = 0x04,

        /// <summary>
        /// Read-only or copy-on-write access to a mapped view of a file mapping object.
        /// </summary>
        /// <remarks>
        /// An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process. 
        /// The private page is marked as <see cref="ReadWrite"/>, and the change is written to the new page.
        /// If <c>Data Execution Prevention</c> is enabled, an attempt to execute code in the committed region results in an access violation.
        /// This flag is not supported by the <see cref="WindowsPinvoke.VirtualAllocEx(IntPtr, IntPtr, uint, WindowsPinvoke.AllocationType, MemoryProtectionFlags)">VirtualAllocEx</see> functions.
        /// </remarks>
        WriteCopy = 0x08,

        TargetsInvalid = 0x40000000,
        TargetsNoUpdate = 0x40000000,
        GuardModifierFlag = 0x100,
        NoCacheModifierFlag = 0x200,
        WriteCombineModifierFlag = 0x400,

        // Flag Combinations (not used by native functions, but convenient still)
        AnyRead = ReadOnly | ReadWrite | ExecuteRead | ExecuteReadWrite,
        AnyWrite = WriteCopy | ReadWrite | ExecuteReadWrite | ExecuteWriteCopy,
        AnyExecute = Execute | ExecuteRead | ExecuteReadWrite | ExecuteWriteCopy,
        AnyReadWriteExecute = AnyRead | AnyWrite | AnyExecute
    }
}

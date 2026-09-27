using System.Diagnostics;
using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;

namespace MemoryShark.Windows.Processes;

/// <summary>Provides Windows process utilities without owning the supplied process's lifetime.</summary>
/// <remarks>
/// This handler and its dependent services belong to one attachment. The caller owns cancellation,
/// cleanup, and Process disposal. Do not close, dispose, or reassociate the supplied Process while
/// operations are running. Construct a new process-bound composition when attaching again;
/// previously resolved addresses and tracked allocations must not carry over to the new target.
/// </remarks>
public class WindowsProcessHandler : IProcessHandler
{
    /// <summary>Creates a handler that borrows the supplied process without taking disposal ownership.</summary>
    /// <param name="process">A process associated with the target for the lifetime of this attachment.</param>
    public WindowsProcessHandler(Process process)
    {
        Process = process ?? throw new ArgumentNullException(nameof(process));
    }

    /// <inheritdoc />
    public Process Process { get; }

    public bool Is64BitProcess
    {
        get
        {
            if (!WindowsPinvoke.IsWow64Process(Process.Handle, out var result))
                throw new PinvokeException(nameof(WindowsPinvoke.IsWow64Process), Marshal.GetLastPInvokeError());

            return !result;
        }
    }

    public ProcessModule? GetModuleByName(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentNullException(nameof(name), $"{nameof(name)} cannot be null or empty.");

        var result = Process.Modules.Cast<ProcessModule>().SingleOrDefault(module => string.Equals(name, module.ModuleName, StringComparison.OrdinalIgnoreCase));

        return result;
    }
}

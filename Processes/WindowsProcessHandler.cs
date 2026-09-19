using System.Diagnostics;
using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;

namespace MemoryShark.Windows.Processes;

public class WindowsProcessHandler : IProcessHandler
{
    public WindowsProcessHandler(Process process)
    {
        Process = process ?? throw new ArgumentNullException(nameof(process));
    }

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

        var result = Process.Modules.Cast<ProcessModule>().SingleOrDefault(module =>
            string.Equals(name, module.ModuleName, StringComparison.OrdinalIgnoreCase));

        return result;
    }
}
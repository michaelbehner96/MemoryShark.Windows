using MemoryShark.Exceptions;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MemoryShark.Windows.Processes
{
    public class WindowsProcessHandler : IProcessHandler
    {
        public Process Process { get; private set; }

        public bool Is64BitProcess
        {
            get
            {
                if (!WindowsPinvoke.IsWow64Process(Process.Handle, out bool result))
                    throw new PinvokeException(nameof(WindowsPinvoke.IsWow64Process), Marshal.GetLastPInvokeError());
                else
                    return !result;
            }
        }

        public WindowsProcessHandler(Process process)
        {
            this.Process = process ?? throw new ArgumentNullException(nameof(process));
        }

        public ProcessModule? GetModuleByName(string name)
        {
            if (String.IsNullOrEmpty(name))
                throw new ArgumentNullException(nameof(name), $"{nameof(name)} cannot be null or empty.");

            var result = Process.Modules.Cast<ProcessModule>().SingleOrDefault(module => string.Equals(name, module.ModuleName, StringComparison.OrdinalIgnoreCase));

            return result;
        }
    }
}

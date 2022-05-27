using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
                    throw new Exception();
                else
                    return !result;
            }
        }

        public WindowsProcessHandler(Process process)
        {
            this.Process = process ?? throw new ArgumentNullException(nameof(process));
        }
    }
}

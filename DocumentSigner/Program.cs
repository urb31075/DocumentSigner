using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DocumentSigner
{
    using System.IO;
    using System.Runtime.InteropServices;

    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
            AppDomain.CurrentDomain.UnhandledException += DumpMaker.CurrentDomain_UnhandledException;
            Application.Run(new DocumentSugnerForm());
        }

        public static class DumpMaker 
        {
            private static class MINIDUMP_TYPE
            {
                public const int MiniDumpNormal = 0x00000000;
                public const int MiniDumpWithCodeSegs = 0x00002000;
            }

            [DllImport("kernel32.dll")]
            static extern uint GetCurrentThreadId();

            [DllImport("Dbghelp.dll")]
            static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, ref MINIDUMP_EXCEPTION_INFORMATION ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

            public struct MINIDUMP_EXCEPTION_INFORMATION
            {
                public uint ThreadId;
                public IntPtr ExceptionPointers;
                public int ClientPointers;
            }

            public static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
            {
                System.Windows.Forms.MessageBox.Show("Unhandled exception!");

                CreateMiniDump();
            }

            private static void CreateMiniDump()
            {
                using (System.Diagnostics.Process process = System.Diagnostics.Process.GetCurrentProcess())
                {
                    string FileName = string.Format(@"CRASH_DUMP_{0}_{1}.dmp", DateTime.Today.ToShortDateString(), DateTime.Now.Ticks);

                    MINIDUMP_EXCEPTION_INFORMATION Mdinfo = new MINIDUMP_EXCEPTION_INFORMATION();

                    Mdinfo.ThreadId = GetCurrentThreadId();
                    Mdinfo.ExceptionPointers = Marshal.GetExceptionPointers();
                    Mdinfo.ClientPointers = 1;

                    using (FileStream fs = new FileStream(FileName, FileMode.Create))
                    {
                        {
                            MiniDumpWriteDump(process.Handle, (uint)process.Id, fs.SafeFileHandle.DangerousGetHandle(), MINIDUMP_TYPE.MiniDumpNormal,
                            ref Mdinfo,
                            IntPtr.Zero,
                            IntPtr.Zero);
                        }
                    }
                }
            }            
        }
    }
}

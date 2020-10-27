using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PJ64Launcher
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            string keyGenExe = "PJ64KeyGen.exe";
            string exe = "Project64.exe";

            if (!File.Exists(keyGenExe))
            {
                MessageBox.Show("KeyGen Executable Missing!", "Error", MessageBoxButtons.OK,  MessageBoxIcon.Error);
                return;
            }

            if (!File.Exists(exe))
            {
                MessageBox.Show("Project64 Executable Missing!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            Process p = new Process();

            // launch keygen
            p.StartInfo = new ProcessStartInfo()
            {
                FileName = keyGenExe,
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            p.Start();
            p.WaitForExit();

            // launch pj64
            p.StartInfo = new ProcessStartInfo()
            {
                FileName = exe,
                CreateNoWindow = false,
                UseShellExecute = false,
            };
            p.Start();
            p.WaitForExit();
        }
    }
}

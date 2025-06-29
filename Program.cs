using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyTabs;

namespace PacketHunter3
{
    internal static class Program
    {

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_HIDE = 0;  // Constante pour cacher la fenêtre
        private const int SW_SHOW = 5;  // Constante pour montrer la fenêtre
        private const int SW_MINIMIZE = 6;   // Constante pour minimiser la fenêtre

        /// <summary>
        /// Point d'entrée principal de l'application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Console.Title = "Xiniths Packet Hunter Ultimate";
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (!File.Exists("DebugConsole.config"))
            {
                IntPtr consoleWindow = GetConsoleWindow();

                // Cacher la fenêtre de la console
                ShowWindow(consoleWindow, SW_HIDE);
            }
            if (!File.Exists("DefaultRenderer.config"))
            {
                ContainerForm container = new ContainerForm();
                container.Tabs.Add(
                    new TitleBarTab(container)
                    {
                        Content = new Form1
                        {
                            Text = "Nouvelle onglet"
                        }
                    });
                container.SelectedTabIndex = 0;
                TitleBarTabsApplicationContext applicationContext = new TitleBarTabsApplicationContext();
                applicationContext.Start(container);
                Application.Run(applicationContext);
            }
            else
            {
                Form1 main = new Form1();

                // Exécutez l'application en passant l'instance de Form1 à Application.Run
                Application.Run(main);
            }
           
        }
    }
}

using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace PacketHunter3
{
    public partial class ConnectTest : Form
    {
        [DllImport("wlanapi.dll", SetLastError = true)]
        public static extern uint WlanOpenHandle(
            uint dwClientVersion,
            IntPtr pReserved,
            out uint pdwNegotiatedVersion,
            out IntPtr phClientHandle
        );

        [DllImport("wlanapi.dll", SetLastError = true)]
        public static extern uint WlanHostedNetworkStartUsing(
            IntPtr hClientHandle,
            out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pReserved
        );

        [DllImport("wlanapi.dll", SetLastError = true)]
        public static extern uint WlanCloseHandle(
            IntPtr hClientHandle,
            IntPtr pReserved
        );

        public enum WLAN_HOSTED_NETWORK_REASON
        {
            wlan_hosted_network_reason_success = 0,
            // Add more possible reasons as needed
        }

        public ConnectTest()
        {
            InitializeComponent();
        }

        private void LogMessage(string message)
        {
            richTextBoxLog.AppendText($"{DateTime.Now}: {message}\n");
            richTextBoxLog.ScrollToCaret();
        }

        private void LogErrorMessage(string methodName, uint errorCode)
        {
            LogMessage($"{methodName} failed with error code: {errorCode}");
            // Retrieve more detailed error message using the errorCode and log it
        }

        private void button1_Click(object sender, EventArgs e)
        {
            uint negotiatedVersion;
            IntPtr clientHandle;

            uint result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);

            if (result == 0)
            {
                WLAN_HOSTED_NETWORK_REASON failReason;
                result = WlanHostedNetworkStartUsing(clientHandle, out failReason, IntPtr.Zero);

                if (result == 0)
                {
                    LogMessage("Wi-Fi hotspot created successfully!");
                }
                else
                {
                    LogErrorMessage("WlanHostedNetworkStartUsing", result);
                    LogMessage($"Failed to start hosted network. Reason: {failReason}");
                }

                WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
            else
            {
                LogErrorMessage("WlanOpenHandle", result);
                LogMessage($"Failed to open handle to WLAN API. Error code: {result}");
            }
        }
    }
}

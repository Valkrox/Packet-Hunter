using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.AxHost;
using System.Diagnostics;
using System.Reflection.Emit;
using System.Text.RegularExpressions;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using System.IO;
using System.Runtime.InteropServices;

namespace PacketHunter3
{
    public partial class Form1 : Form
    {

        private Socket socket;
        private Thread listenThread;
        private NetworkInterface[] networkInterfaces;
        private Socket socketz = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        private byte[] bytedata = new byte[4096];
        private IPAddress myip;
        private bool started = false;
        private Size sizediff;
        private bool formloaded = false;
        private IPAddress FilterIPAddress = new IPAddress(0);
        private bool FilterIP;
        private NetworkInterface[] mycomputerconnections;
        private string srsprot;
        private string destprot;
        private int checksumErrorsCount = 0;
        private int pckcount = 0;
        private Thread snifferThread;
        private List<ICMPPacket> icmpPackets;
        private Socket socketp;
        private AutoResetEvent packetCapturedEvent = new AutoResetEvent(false);
        private string Typedephrase = "";


        private string stringz = "";
        private string Typez = "";
        private IPAddress ipfrom;
        private IPAddress ipto;
        private uint destinationport;
        private uint sourceport;
        private string headerss = "";
        int nombrePaquets = 0;
        double sommeTailles = 0;
        double moyenneTaille = 0;



        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern void FreeMibTable(IntPtr plpNetTable);

        public const int ERROR_INSUFFICIENT_BUFFER = 122;

        public struct MIB_IPNETROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint dwIndex;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwPhysAddrLen;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac0;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac1;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac2;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac3;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac4;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac5;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac6;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac7;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwAddr;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwType;
        }

        public Form1()
        {
            var headerItem = Header.Item.Normal;


            Console.WriteLine($"VisualStyleElement HeaderItem: {headerItem}");
            InitializeComponent();
            panel1.Dock = DockStyle.Fill;
        }

        private void StartSniffing(NetworkInterface selectedInterface)
        {
            try
            {
                socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IP);
                socket.Bind(new IPEndPoint(selectedInterface.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetworkV6)?.Address, 0));
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, true);

                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                byte[] byOut = new byte[4] { 1, 0, 0, 0 };

                socket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);

                listenThread = new Thread(new ThreadStart(ListenForData));
                listenThread.Start();
            }
            catch (SocketException ex)
            {
                MessageBox.Show($"Erreur lors de la création du socket : {ex.Message}", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.Close(); 
            }
        }

        private void ListenForData()
        {
            byte[] buffer = new byte[4096];

            while (true)
            {
                try
                {
                    int bytesRead = socket.Receive(buffer, SocketFlags.None);

     
                    ParseAndDisplayIPv6Packet(buffer, bytesRead);
                }
                catch (SocketException ex)
                {
                    MessageBox.Show($"Erreur lors de la réception des données : {ex.Message}", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.Close(); 
                }
            }
        }

        private void ParseAndDisplayIPv6Packet(byte[] buffer, int length)
        {

            int taillePaquet = length;
            AnalyserTaillePaquets(taillePaquet);

            IPAddress sourceIPAddress = new IPAddress(buffer.Skip(8).Take(16).ToArray());
            IPAddress destinationIPAddress = new IPAddress(buffer.Skip(24).Take(16).ToArray());


            ushort checksum = BitConverter.ToUInt16(buffer.Skip(6).Take(2).ToArray(), 0);
            LogInfo($"IPv6 Checksum: {checksum}");

            uint sequenceNumber = BitConverter.ToUInt32(buffer.Skip(44).Take(4).Reverse().ToArray(), 0);
            LogInfo($"TCP Sequence Number: {sequenceNumber}");

            int sourcePort = BitConverter.ToUInt16(buffer.Skip(40).Take(2).Reverse().ToArray(), 0);
            int destinationPort = BitConverter.ToUInt16(buffer.Skip(42).Take(2).Reverse().ToArray(), 0);

            byte sourceProtocol = buffer[39];
            byte destinationProtocol = buffer[41];
            byte protocol = buffer[39];
            LogInfo($"Protocol: {protocol}");


            srsprot = "";
            destprot = "";

            if (sourceport == 80)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 80)
            {
                destprot = "HTTP";
            }

            if (sourceport == 8080)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 8080)
            {
                destprot = "HTTP";
            }

            if (sourceport == 443)
            {
                srsprot = "HTTPS";
            }

            if (destinationport == 443)
            {
                destprot = "HTTPS";
            }
            if (sourceport == 15)
            {
                srsprot = "Netstat";
            }

            if (destinationport == 15)
            {
                destprot = "Netstat";
            }





            string sourceAddress = sourceIPAddress.ToString();
            string destinationAddress = destinationIPAddress.ToString();


            string type = "Autre";
            if (protocol == 6)
            {
                type = "TCPV6";
            }
            else if (protocol == 17)
            {
                type = "UDPV6";
            }
            else if (protocol == 58)
            {
                type = "ICMPv6";
            }
            else if (protocol == 0)
            {
                type = "Hop-by-Hop Options";
            }
            else if (protocol == 43)
            {
                type = "Routing Header for IPv6";
            }
            else if (protocol == 44)
            {
                type = "Fragment Header for IPv6";
            }
            else if (protocol == 50)
            {
                type = "ESP";
            }
            else if (protocol == 51)
            {
                type = "AH";
            }
            else if (protocol == 59)
            {
                type = "No Next Header";
            }
            else if (protocol == 60)
            {
                type = "Destination Options for IPv6";
            }
            else if (protocol == 135)
            {
                type = "Mobility Header for IPv6";
            }
            else if (protocol == 139)
            {
                type = "HIP";
            }

            int packetSize = length;

            byte[] packetContent = buffer.Skip(40).ToArray(); 


            string asciiContent = Encoding.UTF8.GetString(packetContent);


            if (started == false)
            {
                return;
            }
            pckcount++;
            if (checkBox1.Checked == true)
            {
                listView1.Invoke(new Action(() =>
                {
                    ListViewItem item = new ListViewItem(sourceAddress);
                    item.SubItems.Add(destinationAddress);
                    item.SubItems.Add(sourcePort.ToString());
                    item.SubItems.Add(destinationPort.ToString());
                    item.SubItems.Add(srsprot.ToString()); 
                    item.SubItems.Add(destprot.ToString());
                    item.SubItems.Add(type + $":{protocol}");
                    item.SubItems.Add(packetSize.ToString());
                    item.SubItems.Add(asciiContent);
                    item.SubItems.Add(BitConverter.ToString(packetContent));

                    listView1.Items.Add(item);
                    if (checkBox2.Checked == true)
                    {
                        item.EnsureVisible();
                    }
                }));
            }
            else
            {
                DGV.Invoke(new Action(() =>
                {
                    DGV.Rows.Add(sourceAddress, destinationAddress, sourcePort, destinationPort, sourceProtocol, destinationProtocol, type + $":{protocol}", packetSize, asciiContent, BitConverter.ToString(packetContent));
                }));
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (started == true)
            {
                MessageBox.Show("Impossible de fermer l'application tant qu'elle est en mode écoute.\nVeuilliez d'abord cliquer sur le bouton STOP pour éteindre/fermer l'onglet.");
                e.Cancel = true;
            }

            if (socket != null)
            {
                socket.Close();
            }

            if (listenThread != null && listenThread.IsAlive)
            {
                listenThread.Abort();
            }
        }

        private void comboBoxInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (comboBoxInterfaces.SelectedIndex >= 0)
            {
                try
                {
                string selectedInterfaceDescription = comboBoxInterfaces.SelectedItem.ToString();
                NetworkInterface selectedInterface = networkInterfaces.FirstOrDefault(nic => nic.Description == selectedInterfaceDescription);



                if (selectedInterface.Supports(NetworkInterfaceComponent.IPv6))
                {

                    if (selectedInterface.GetIPProperties().UnicastAddresses.Any(addr => addr.Address.AddressFamily == AddressFamily.InterNetworkV6))
                    {

                            LogInfo("Le sniffing à commencer sur l'interface : " + selectedInterface.Name.ToString());
                        StartSniffing(selectedInterface);
                    }
                    else
                    {
                        MessageBox.Show("L'interface réseau sélectionnée n'a pas d'adresse IPv6 valide.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            LogMessage("L'interface réseau sélectionnée n'a pas d'adresse IPv6 valide.");
                            this.Close();
                    }
                }
                else
                {
                    MessageBox.Show("L'interface réseau sélectionnée ne prend pas en charge IPv6.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        LogMessage("L'interface réseau sélectionnée ne prend pas en charge IPv6.");
                    this.Close();
                }                
                }
                catch(Exception ex)
                {
                    MessageBox.Show("Votre Interface ne prend peut être pas IPV6/IPV4\nLe Sniffing Fonctionnera, mais une de ces deux fonction ne sera pas affichés.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    LogTrace(ex.Message);
                }
            }


            if (comboBoxInterfaces.SelectedIndex == -1)
            {
                MessageBox.Show("Veuillez sélectionner une interface réseau.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }


            snifferThread = new Thread(new ThreadStart(StartSniffing));
            snifferThread.Start();

            for (int i = 0; i < mycomputerconnections[comboBoxInterfaces.SelectedIndex].GetIPProperties().UnicastAddresses.Count; i++)
            {
                if (mycomputerconnections[comboBoxInterfaces.SelectedIndex].GetIPProperties().UnicastAddresses[i].Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    myip = mycomputerconnections[comboBoxInterfaces.SelectedIndex].GetIPProperties().UnicastAddresses[i].Address;
                    BindSocket();
                }
            }
        }

        public bool enableARP = false;

        private void Form1_Load(object sender, EventArgs e)
        {
            timer1.Start();
            if(enableARP == true)
            {
                System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
                timer.Tick += new EventHandler(RefreshARPTable);
                timer.Interval = 1000; 
                timer.Start();
            }

            this.DoubleBuffered = true;
            LogTrace("Démarrage du logiciel");
            sizediff.Height = this.Height - DGV.Height;
            sizediff.Width = this.Width - DGV.Width;
            formloaded = true;

            icmpPackets = new List<ICMPPacket>();

            mycomputerconnections = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface nic in mycomputerconnections)
            {
                comboBoxInterfaces.Items.Add(nic.Description);
                LogInfo($"Added in ComboBox: {nic.Description}");
                LogInfo($"Interface Info: Name: {nic.Name} Id: {nic.Id} Speed: {nic.Speed} NetworkInterfaceType: {nic.NetworkInterfaceType} Description: {nic.Description} OperationalStatus: {nic.OperationalStatus}");
            }

            LogInfo($"Le logiciel à correctement démarrer !");
            LogInfo($"Hello, World !");
        }

        private string[] initialARPTable;
        private void RefreshARPTable(object sender, EventArgs e)
        {
            listBox1.Items.Clear();
            GetARPTable();
                listBox1.Items.Clear();
                string[] arpTable = GetARPTableContents();
                foreach (var entry in arpTable)
                {
                    listBox1.Items.Add(entry);
                }

        }

        private string[] GetARPTableContents()
        {
            string[] arpTable = new string[] { };

            try
            {
                StringBuilder tableBuilder = new StringBuilder();

                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties properties = ni.GetIPProperties();

                       foreach (var item in properties.UnicastAddresses)
                        {
                            tableBuilder.AppendLine($"Interface: {ni.Name} - {item.Address}");
                        }
                    }
                }

                string tableContent = tableBuilder.ToString();
                arpTable = tableContent.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de la récupération de la table ARP : {ex.Message}");
            }

            return arpTable;
        }

        private void GetARPTable()
        {
            IntPtr pTable = IntPtr.Zero;
            int bytesNeeded = 0;

            try
            {
                int result = GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);
                if (result != ERROR_INSUFFICIENT_BUFFER)
                {
                    return;
                }

                pTable = Marshal.AllocCoTaskMem(bytesNeeded);
                result = GetIpNetTable(pTable, ref bytesNeeded, false);

                if (result != 0)
                {
                    return;
                }

                int entries = Marshal.ReadInt32(pTable);

                IntPtr currentBuffer = new IntPtr(pTable.ToInt64() + Marshal.SizeOf(typeof(int)));

                for (int index = 0; index < entries; ++index)
                {
                    MIB_IPNETROW row = (MIB_IPNETROW)Marshal.PtrToStructure(currentBuffer, typeof(MIB_IPNETROW));
                    string macAddress = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                    string ipAddress = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                    listBox1.Items.Add($"IP: {ipAddress}, MAC: {macAddress}");
                    currentBuffer = new IntPtr(currentBuffer.ToInt64() + Marshal.SizeOf(typeof(MIB_IPNETROW)));
                }
            }
            finally
            {
                if (pTable != IntPtr.Zero)
                {
                    FreeMibTable(pTable);
                }
            }
        }



        //-------------------------------------------------------------------------------------------------------------------------------------------------
        //IPV4
        //-------------------------------------------------------------------------------------------------------------------------------------------------

        private void LogTrace(string v)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[{System.DateTime.Now} Packet Reader : {v}");
            Console.ForegroundColor = ConsoleColor.White;
        }

        private void LogMessage(string v)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[{System.DateTime.Now} Packet Reader : {v}");
            Console.ForegroundColor = ConsoleColor.White;
        }

        private void LogInfo(string v)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"[{System.DateTime.Now} Packet Reader : {v}");
            Console.ForegroundColor = ConsoleColor.White;
        }

        private void LogAvert(string v)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{System.DateTime.Now} Packet Reader : /!\\  {v}");
            Console.ForegroundColor = ConsoleColor.White;
        }

        private void OnReceive(IAsyncResult asyncresult)
        {
            if (started == true)
            {
                try
                {
                    if (label4.InvokeRequired)
                    {
                        label4.Invoke((MethodInvoker)delegate
                        {
                            label4.Text = "Nombres de packets analyser : " + pckcount.ToString();
                        });
                    }
                }
                catch (Exception ex)
                {
                    LogTrace($"Error : {ex.Message}");
                }
                pckcount++;

                uint readlength = BitConverter.ToUInt16(Byteswap(bytedata, 2), 0);
                sourceport = BitConverter.ToUInt16(Byteswap(bytedata, 22), 0);
                destinationport = BitConverter.ToUInt16(Byteswap(bytedata, 24), 0);


                int ipHeaderLength = (bytedata[0] & 15) * 4;
                ushort ipHeaderChecksum = BitConverter.ToUInt16(bytedata, 10);
                ushort calculatedChecksum = CalculateIPChecksum(bytedata, 0, ipHeaderLength);


                if (calculatedChecksum != ipHeaderChecksum)
                {

                    this.Invoke((MethodInvoker)delegate
                    {
                        try
                        {
                            checksumErrorsCount++;
                            Debug.WriteLine("Checksum Error - Calculated: " + calculatedChecksum + ", IP Header: " + ipHeaderChecksum);
                        }
                        catch (Exception ex)
                        {
                            LogTrace($"Error : {ex.Message}");
                        }
                    });
                }

                if (bytedata[9] == 6)
                {
                    Typez = "TCP";
                }
                else if (bytedata[9] == 17)
                {
                    Typez = "UDP";
                }
                else
                {
                    Typez = "???";
                }


                ipfrom = new IPAddress(BitConverter.ToUInt32(bytedata, 12));
                ipto = new IPAddress(BitConverter.ToUInt32(bytedata, 16));


                if ((ipfrom.Equals(myip) == true || ipto.Equals(myip) == true) && ipto.Equals(ipfrom) == false)
                {
                    if (FilterIP == false || (FilterIP == true && (FilterIPAddress.Equals(ipfrom) || FilterIPAddress.Equals(ipto))))
                    {

                        stringz = "";
                        for (int i = 26; i < readlength; i++)
                        {
                            if (char.IsLetterOrDigit((char)bytedata[i]) == true)
                            {
                                stringz = stringz + (char)bytedata[i];
                            }
                            else
                            {
                                stringz = stringz + ".";
                            }
                        }


                        if (stringz.Contains("HTTP/1."))
                        {

                            string headers = ExtractHTTPHeaders(stringz);


                            DGV.Invoke((MethodInvoker)DGVUpdateWithHeaders);
                        }
                        else
                        {

                            DGV.Invoke((MethodInvoker)DGVUpdate);
                        }
                    }
                }
            }


            socketz.BeginReceive(bytedata, 0, bytedata.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }

        private string ExtractHTTPHeaders(string data)
        {
            string headerss = "";
            Regex headerRegex = new Regex("(.*?: .*?)(?:\r\n|$)");

            MatchCollection headerMatches = headerRegex.Matches(data);
            foreach (Match headerMatch in headerMatches)
            {
                headerss += headerMatch.Value + "\r\n";
            }

            return headerss;
        }

        private ushort CalculateIPChecksum(byte[] packet, int offset, int length)
        {
            uint sum = 0;

            for (int i = offset; i < offset + length; i += 2)
            {
                sum += BitConverter.ToUInt16(packet, i);
            }

            if (length % 2 == 1)
            {
                sum += packet[offset + length - 1];
            }

            while ((sum >> 16) > 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)~sum;
        }

        private void DGVUpdateWithHeaders()
        {
            srsprot = "";
            destprot = "";

            if (DGV.Rows.Count > 50)
            {
                DGV.Rows.RemoveAt(0);
            }

            if (sourceport == 80)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 80)
            {
                destprot = "HTTP";
            }

            if (sourceport == 8080)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 8080)
            {
                destprot = "HTTP";
            }

            if (sourceport == 443)
            {
                srsprot = "HTTPS";
            }

            if (destinationport == 443)
            {
                destprot = "HTTPS";
            }

            if (sourceport == 15)
            {
                srsprot = "Netstat";
            }

            if (destinationport == 15)
            {
                destprot = "Netstat";
            }


            if (sourceport == 21)
            {
                if(Typez == "TCP")
                {
                    srsprot = "FTP";
                }

            }

            if (destinationport == 21)
            {
                if (Typez == "TCP")
                {
                    destprot = "FTP";
                }
            }

            if (sourceport == 23)
            {
                if (Typez == "TCP")
                {
                    srsprot = "TELNET";
                }

            }

            if (destinationport == 23)
            {
                if (Typez == "TCP")
                {
                    destprot = "TELNET";
                }
            }

            if (sourceport == 23)
            {
                if (Typez == "TCP")
                {
                    srsprot = "SMTP";
                }

            }

            if (destinationport == 25)
            {
                if (Typez == "TCP")
                {
                    destprot = "SMTP";
                }
            }


            int taillePaquet = stringz.Length;
            AnalyserTaillePaquets(taillePaquet);

            pckcount++;
            if (checkBox1.Checked == true)
            {
                ListViewItem item = new ListViewItem(ipfrom.ToString()); 
                item.SubItems.Add(ipto.ToString()); 
                item.SubItems.Add(sourceport.ToString()); 
                item.SubItems.Add(destinationport.ToString()); 
                item.SubItems.Add(srsprot); 
                item.SubItems.Add(destprot); 
                item.SubItems.Add(Typez); 
                item.SubItems.Add(""); 
                item.SubItems.Add(stringz);
                item.SubItems.Add(headerss);

                listView1.Items.Add(item);

                if (checkBox2.Checked == true)
                {
                    item.EnsureVisible();
                }

            }
            else
            {
                DGV.Rows.Add();
                DGV.Rows[DGV.Rows.Count - 1].Cells[0].Value = ipfrom.ToString(); 
                DGV.Rows[DGV.Rows.Count - 1].Cells[1].Value = ipto.ToString(); 
                DGV.Rows[DGV.Rows.Count - 1].Cells[2].Value = sourceport; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[3].Value = destinationport; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[4].Value = srsprot; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[5].Value = destprot; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[6].Value = Typez; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[8].Value = stringz; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[9].Value = headerss; 
            }
        }

        void AnalyserTaillePaquets(int taillePaquet)
        {
            nombrePaquets++;
            sommeTailles += taillePaquet;
            moyenneTaille = sommeTailles / nombrePaquets;
            LogMessage("moyenne Taille  " + moyenneTaille.ToString());

            label3.Invoke((MethodInvoker)delegate {
                label3.Text = $"Taille moyenne : {moyenneTaille}";
            });

 
            double seuil = moyenneTaille * 1.5; 


            if (taillePaquet > seuil)
            {

                LogAvert($"Anomalie détectée : Taille du paquet : {taillePaquet} (Seuil : {seuil})");
                listView2.Invoke((MethodInvoker)delegate
                {
                    listView2.Items.Add($"Anomalie détectée : Taille du paquet : {taillePaquet} (Seuil : {seuil})");
                });
                EnregistrerEvenementAnomalieTaille(taillePaquet, seuil);
            }
        }

        void EnregistrerEvenementAnomalieTaille(int taillePaquet, double seuil)
        {
                LogAvert($"Anomalie de taille détectée : Taille du paquet : {taillePaquet} (Seuil : {seuil})");
        }

        private void DGVUpdate()
        {
            srsprot = "";
            destprot = "";


            if (DGV.Rows.Count > 50)
            {
                DGV.Rows.RemoveAt(0);
            }

            if (sourceport == 80)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 80)
            {
                destprot = "HTTP";
            }

            if (sourceport == 443)
            {
                srsprot = "HTTPS";
            }

            if (destinationport == 443)
            {
                destprot = "HTTPS";
            }
            if (sourceport == 21)
            {
                srsprot = "FTP";
            }

            if (destinationport == 21)
            {
                destprot = "FTP";
            }

            if (sourceport == 22)
            {
                srsprot = "SSH";
            }

            if (destinationport == 22)
            {
                destprot = "SSH";
            }

            if (sourceport == 25)
            {
                srsprot = "SMTP";
            }

            if (destinationport == 25)
            {
                destprot = "SMTP";
            }

            if (sourceport == 53)
            {
                srsprot = "DNS";
            }

            if (destinationport == 53)
            {
                destprot = "DNS";
            }

            if (sourceport == 80)
            {
                srsprot = "HTTP";
            }

            if (destinationport == 80)
            {
                destprot = "HTTP";
            }

            if (sourceport == 110)
            {
                srsprot = "POP3";
            }

            if (destinationport == 110)
            {
                destprot = "POP3";
            }

            if (sourceport == 143)
            {
                srsprot = "IMAP";
            }

            if (destinationport == 143)
            {
                destprot = "IMAP";
            }

            if (sourceport == 443)
            {
                srsprot = "HTTPS";
            }

            if (destinationport == 443)
            {
                destprot = "HTTPS";
            }

            if (sourceport == 3306)
            {
                srsprot = "MySQL";
            }

            if (destinationport == 3306)
            {
                destprot = "MySQL";
            }

            if (sourceport == 3389)
            {
                srsprot = "RDP";
            }

            if (destinationport == 3389)
            {
                destprot = "RDP";
            }

            if (sourceport == 5432)
            {
                srsprot = "PostgreSQL";
            }

            if (destinationport == 5432)
            {
                destprot = "PostgreSQL";
            }
            if (sourceport == 67 || sourceport == 68)
            {
                srsprot = "DHCP";
            }

            if (destinationport == 67 || destinationport == 68)
            {
                destprot = "DHCP";
            }

            if (sourceport == 69)
            {
                srsprot = "TFTP";
            }

            if (destinationport == 69)
            {
                destprot = "TFTP";
            }

            if (sourceport == 123)
            {
                srsprot = "NTP";
            }

            if (destinationport == 123)
            {
                destprot = "NTP";
            }

            if (sourceport == 161)
            {
                srsprot = "SNMP";
            }

            if (destinationport == 161)
            {
                destprot = "SNMP";
            }
            if (sourceport == 1900)
            {
                srsprot = "SSDP";
            }

            if (destinationport == 1900)
            {
                destprot = "SSDP";
            }

            int taillePaquet = stringz.Length;
            AnalyserTaillePaquets(taillePaquet);

            if (checkBox1.Checked == true)
            {
                ListViewItem item = new ListViewItem(ipfrom.ToString());
                item.SubItems.Add(ipto.ToString());
                item.SubItems.Add(sourceport.ToString());
                item.SubItems.Add(destinationport.ToString());
                item.SubItems.Add(srsprot);
                item.SubItems.Add(destprot);
                item.SubItems.Add(Typez); 
                item.SubItems.Add(""); 
                item.SubItems.Add(stringz);
                listView1.Items.Add(item);

                if (checkBox2.Checked == true)
                {
                    item.EnsureVisible();
                }

            }
            else
            {
                DGV.Rows.Add();
                DGV.Rows[DGV.Rows.Count - 1].Cells[0].Value = ipfrom.ToString();
                DGV.Rows[DGV.Rows.Count - 1].Cells[1].Value = ipto.ToString();
                DGV.Rows[DGV.Rows.Count - 1].Cells[2].Value = sourceport;
                DGV.Rows[DGV.Rows.Count - 1].Cells[3].Value = destinationport; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[4].Value = srsprot; 
                DGV.Rows[DGV.Rows.Count - 1].Cells[5].Value = destprot;
                DGV.Rows[DGV.Rows.Count - 1].Cells[6].Value = Typez;
                DGV.Rows[DGV.Rows.Count - 1].Cells[8].Value = stringz;
            }
        }

        private byte[] Byteswap(byte[] bytez, uint index)
        {
            byte[] result = new byte[2];
            result[0] = bytez[index + 1];
            result[1] = bytez[index];
            return result;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (started == true)
            {
                button1.Text = "Start";
                LogMessage("Sniffing Enabled");
                started = false;
            }
            else
            {
                button1.Text = "Stop";
                LogMessage("Sniffing Disabled");
                started = true;
            }
        }

        private void Form1_Resize(object sender, EventArgs e)
        {
            if (formloaded == true)
            {
                DGV.Size = this.Size - sizediff;
            }
        }

        private void TextBox1_TextChanged(object sender, EventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(TextBox1.Text))
                {
                    FilterIPAddress = IPAddress.Parse(TextBox1.Text);
                    FilterIP = true;
                    TextBox1.BackColor = Color.LimeGreen;
                }
                else
                {
                    FilterIP = false;
                    TextBox1.BackColor = Color.White;
                }
            }
            catch (Exception ex)
            {
                FilterIP = false;
                TextBox1.BackColor = Color.White;
                LogTrace($"Error : {ex.Message}");
            }
        }

        private void BindSocket()
        {
            try
            {
                socketz.Bind(new IPEndPoint(myip, 0));
                socketz.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                byte[] bytrue = { 1, 0, 0, 0 };
                byte[] byout = { 1, 0, 0, 0 };
                socketz.IOControl(IOControlCode.ReceiveAll, bytrue, byout);
                socketz.Blocking = false;
                bytedata = new byte[socketz.ReceiveBufferSize];
                socketz.BeginReceive(bytedata, 0, bytedata.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                comboBoxInterfaces.Enabled = false;
            }
            catch (Exception ex)
            {
                comboBoxInterfaces.BackColor = Color.Red;
                LogTrace($"Error : {ex.Message}");
            }
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked == true)
            {
                listView1.Visible = true;
                DGV.Visible = false;
            }
            else
            {
                listView1.Visible = false;
                DGV.Visible = true;
            }
        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            label4.Text = $"Nombres de paquets analysés : {pckcount}";
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------
        //ICMP
        //-------------------------------------------------------------------------------------------------------------------------------------------------

        private void StartSniffing()
        {

            string selectedInterface = string.Empty;
            Invoke(new Action(() => selectedInterface = comboBoxInterfaces.SelectedItem?.ToString()));
            NetworkInterface nic = null;

            foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.Description.Equals(selectedInterface))
                {
                    nic = n;
                    break;
                }
            }


            if (nic == null)
            {
                MessageBox.Show("Interface réseau non trouvée.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }


            UnicastIPAddressInformationCollection ipAddresses = nic.GetIPProperties().UnicastAddresses;


            IPAddress ipAddress = ipAddresses
                .Where(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(addr => addr.Address)
                .FirstOrDefault();

            if (ipAddress == null)
            {
                MessageBox.Show("Aucune adresse IP disponible pour l'interface sélectionnée.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }


            socketp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);


            socketp.Bind(new IPEndPoint(ipAddress, 0));


            socketp.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, new byte[] { 1, 0, 0, 0 });

            byte[] buffer = new byte[4096];

            while (true)
            {
                Debug.Write("ok0");
                Debug.Write("Avant socket.Receive");
                int bytesRead = socketp.Receive(buffer, 0, buffer.Length, SocketFlags.None);
                Debug.Write("Après socket.Receive");

                ICMPPacket icmpPacket = new ICMPPacket(buffer, bytesRead);


                UpdateDataGridView(icmpPacket);
            }
        }

        private void UpdateDataGridView(ICMPPacket icmpPacket)
        {
            Debug.Write("ok1");
            string payloadAscii = Encoding.ASCII.GetString(icmpPacket.Payload);

            if (checkBox1.Checked == true)
            {
                ListViewItem item = new ListViewItem(icmpPacket.SourceIP);
                item.SubItems.Add(icmpPacket.DestinationIP);
                item.SubItems.Add("");
                item.SubItems.Add("");
                item.SubItems.Add("");
                item.SubItems.Add("");
                item.SubItems.Add(icmpPacket.Type.ToString());
                item.SubItems.Add("");
                item.SubItems.Add(payloadAscii);

                listView1.Invoke(new Action(() =>
                {
                    listView1.Items.Add(item);
                }));
            }
            else
            {
                DGV.Invoke(new Action(() =>
                {
                    DGV.Rows.Add(icmpPacket.SourceIP, icmpPacket.DestinationIP, icmpPacket.Type, icmpPacket.Code, icmpPacket.Checksum, payloadAscii);
                }));
            }

        }

        public class ICMPPacket
        {
            public string SourceIP { get; set; }
            public string DestinationIP { get; set; }
            public int Type { get; set; }
            public int Code { get; set; }
            public int Checksum { get; set; }
            public byte[] Payload { get; set; }

            public ICMPPacket(byte[] buffer, int length)
            {
                if (length >= 20) 
                {
                    Type = buffer[20];
                    Code = buffer[21];
                    Checksum = BitConverter.ToUInt16(buffer, 22);

                    IPAddress sourceAddress = new IPAddress(BitConverter.ToUInt32(buffer, 12));
                    IPAddress destinationAddress = new IPAddress(BitConverter.ToUInt32(buffer, 16));
                    SourceIP = sourceAddress.ToString();
                    DestinationIP = destinationAddress.ToString();


                    int payloadOffset = 20 + 8; 
                    int payloadLength = length - payloadOffset;
                    Payload = new byte[payloadLength];
                    Array.Copy(buffer, payloadOffset, Payload, 0, payloadLength);
                }
            }
        }

        //UI
        private void label2_Click(object sender, EventArgs e)
        {
            panel4.Visible = false;
        }

        private void label2_MouseEnter(object sender, EventArgs e)
        {
            label2.ForeColor = Color.Red;
        }

        private void label2_MouseLeave(object sender, EventArgs e)
        {
            label2.ForeColor = Color.White;
        }

        private void panneauBasToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (panneauBasToolStripMenuItem.Checked == true)
            {
                panneauBasToolStripMenuItem.Checked = false;
            }
            else
            {
                panneauBasToolStripMenuItem.Checked = true;
            }
        }

        private void panneauBasToolStripMenuItem_CheckedChanged(object sender, EventArgs e)
        {
            panel4.Visible = panneauBasToolStripMenuItem.Checked;
        }

        private void nmapToolStripMenuItem_Click(object sender, EventArgs e)
        {
        }


        static void RunNmapCommand(string ipAddress, string specifiquesargs)
        {
            try
            {
                string nmapPath = FindNmapPath(); 
                string arg = "";

                if (string.IsNullOrEmpty(nmapPath))
                {
                    MessageBox.Show("Nmap n'a pas été trouvé sur ce système.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (IPAddress.TryParse(ipAddress, out IPAddress ip))
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // IPv4
                    {
                        arg = ""; 
                    }
                    else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) // IPv6
                    {
                        arg = " -6 "; 
                    }
                }

                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/K \"{nmapPath}\" {arg} {specifiquesargs} {ipAddress}",
                    UseShellExecute = true,
                    CreateNoWindow = false
                };

                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de l'exécution de Nmap : {ex.Message}", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static string FindNmapPath()
        {
            string[] possiblePaths = {
        @"C:\Program Files (x86)\Nmap\nmap.exe",
        @"C:\Program Files\Nmap\nmap.exe",

    };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }

            return string.Empty;
        }

        private void scanNormalnoArgToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;

                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scanNormalnoArgToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void détécterLesServicesEtLesVersionssVToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sV ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void détécterLesServicesEtLesVersionssVToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sV ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scannerToutLesPortsTCPsTToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sT ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scannerToutLesPortsTCPsTToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sT ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scannerToutLesPortsUDPsUToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sU ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scannerToutLesPortsUDPsUToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sU ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scanRapideToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-F ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void scanRapideToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-F ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPNullScanToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sN ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPNullScansNToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sN ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPFinScansFToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sF ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPFinScansFToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sF ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPXmasScansXToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sX ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void tCPXmasScansXToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sX ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void analyseFurtivesSToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[0].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sS ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void analyseFurtivesSToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                string ipAddress = listView1.SelectedItems[0].SubItems[1].Text;


                LogMessage("Adresse IP à scanner : " + ipAddress);

                string Arg = "-sS ";

                RunNmapCommand(ipAddress, Arg);
            }
            else
            {
                MessageBox.Show("Aucune ligne sélectionnée dans ListView.\nRemarque : Les outils ne fonctionnent qu'en mode \"Affichage avancé\"", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {

                if (listView1.SelectedItems[0].SubItems.Count >= 9)
                {
                    string content = listView1.SelectedItems[0].SubItems[8].Text; 
                    radioButton1.Checked = true;
                    richTextBox1.Text = content;
                }
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            if(radioButton1.Checked == true)
            {
                if (listView1.SelectedItems.Count > 0)
                {

                    if (listView1.SelectedItems[0].SubItems.Count >= 9)
                    {
                        string content = listView1.SelectedItems[0].SubItems[8].Text; 
                        richTextBox1.Text = content;
                    }
                }
            }
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton2.Checked == true)
            {
                if (listView1.SelectedItems.Count > 0)
                {

                    if (listView1.SelectedItems[0].SubItems.Count >= 9)
                    {
                        string content = listView1.SelectedItems[0].SubItems[8].Text; 
                        byte[] byteArray = Encoding.UTF8.GetBytes(content);
                        string hexString = BitConverter.ToString(byteArray).Replace("-", ""); 
                        richTextBox1.Text = hexString; 
                    }
                }
            }
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton3.Checked == true)
            {
                if (listView1.SelectedItems.Count > 0)
                {

                    if (listView1.SelectedItems[0].SubItems.Count >= 9)
                    {
                        string content = listView1.SelectedItems[0].SubItems[8].Text; 
                        byte[] byteArray = Encoding.UTF8.GetBytes(content);
                        string binaryString = string.Join(" ", byteArray.Select(b => Convert.ToString(b, 2).PadLeft(8, '0'))); 
                        richTextBox1.Text = binaryString;
                    }
                }
            }
        }

        private void radioButton4_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton4.Checked == true)
            {
                if (listView1.SelectedItems.Count > 0)
                {

                    if (listView1.SelectedItems[0].SubItems.Count >= 9)
                    {
                        string content = listView1.SelectedItems[0].SubItems[8].Text; 
                        byte[] asciiBytes = Encoding.ASCII.GetBytes(content);
                        string asciiString = BitConverter.ToString(asciiBytes).Replace("-", " ");
                        richTextBox1.Text = asciiString; 
                    }
                }
            }
        }

        private void radioButton5_CheckedChanged(object sender, EventArgs e)
        {
            try
            {
                if (radioButton5.Checked == true)
                {
                    string hexString = richTextBox1.Text; 

                    string[] hexValuesSplit = hexString.Split(' ');

                    byte[] bytes = new byte[hexValuesSplit.Length];
                    for (int i = 0; i < hexValuesSplit.Length; i++)
                    {
                        bytes[i] = Convert.ToByte(hexValuesSplit[i], 16);
                    }

                    string text = Encoding.UTF8.GetString(bytes);
                    richTextBox1.Text = text;
                }
            }
            catch
            {
                MessageBox.Show("Erreur");
            }
        }


        private void button2_Click(object sender, EventArgs e)
        {
            richTextBox1.SelectAll();
            richTextBox1.Copy();
            richTextBox1.DeselectAll();
        }

        private void fakeComputerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Form2 form2 = new Form2();
            form2.Show();
        }

        private void gestionnaireDeConnexionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ConnexionListen connexionListen = new ConnexionListen();
            connexionListen.Show();
        }

        private void wireShareToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ConnectTest connectTest = new ConnectTest();
            connectTest.Show();
        }
        private void packetHunterToolStripMenuItem_Click(object sender, EventArgs e)
        {
            panel1.Visible = true;
        }

        private void textBox2_KeyDown(object sender, KeyEventArgs e)
        {
        }



        private string ConvertirEnHexadecimal(string texte)
        {
            byte[] bytes = Encoding.Default.GetBytes(texte);
            return BitConverter.ToString(bytes).Replace("-", "");
        }




        private void MinimiserApplication()
        {
            this.WindowState = FormWindowState.Minimized;
        }








        private void toutCopierToolStripMenuItem_Click(object sender, EventArgs e)
        {
            richTextBox1.SelectAll();
            richTextBox1.Copy();
            richTextBox1.DeselectAll();
        }

        private void copierSéléctionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            richTextBox1.Copy();
        }

        private void toutSupprimerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            richTextBox1.Text = "";
        }
    }
}
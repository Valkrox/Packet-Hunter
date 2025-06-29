using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using System.Net.Mail;

namespace PacketHunter3
{
    public partial class Form2 : Form
    {
        public bool started = false;
        private string assignedIPAddress;
        public string macadresse;
        private bool isDragging = false;
        private Point customCursorPosition = new Point(10, 10); // Coordonnées du curseur personnalisé
        public Form2()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            started = true;
            button1.Enabled = false;
            InitializeOS();
            //StartFakeComputer();
        }

        private Point windowPosition = new Point(20, 20); // Position initiale de la fenêtre en pixels
        private Size windowSize = new Size(80, 60); // Taille de la fenêtre en pixels
        private void InitializeOS()
        {
            this.DoubleBuffered = true;
            panel1.BackColor = SystemColors.Window;
            panel1.Paint += new PaintEventHandler(DrawTaskbar); // Dessiner la barre des tâches
            panel1.Paint += new PaintEventHandler(DrawWindow); // Dessiner la fenêtre miniature
            panel1.Paint += new PaintEventHandler(DrawCustomCursor); // Dessiner le curseur personnalisé
            panel1.MouseDown += new MouseEventHandler(panel1_MouseDown); // Début du déplacement de la fenêtre
            panel1.MouseMove += new MouseEventHandler(panel1_MouseMove); // Déplacement de la fenêtre
            panel1.MouseUp += new MouseEventHandler(panel1_MouseUp); // Fin du déplacement de la fenêtre
        }

        private void DrawWindow(object sender, PaintEventArgs e)
        {
            // Dessiner la fenêtre miniature en utilisant les coordonnées windowPosition et la taille windowSize
            e.Graphics.FillRectangle(Brushes.LightGray, windowPosition.X, windowPosition.Y, windowSize.Width, windowSize.Height);
        }

        private void DrawTaskbar(object sender, PaintEventArgs e)
        {
            // Dessiner la barre des tâches avec une hauteur de 5 pixels
            Pen pen = new Pen(Color.Gray, 5);
            e.Graphics.DrawLine(pen, 0, panel1.Height - 5, panel1.Width, panel1.Height - 5);
        }


        private void DrawCustomCursor(object sender, PaintEventArgs e)
        {
            // Dessiner un curseur personnalisé en forme de flèche penchée légèrement vers la gauche avec une base plus large pour simuler une souris

            // Dessin d'un triangle penché légèrement vers la gauche pour représenter la flèche
            Point[] arrowPoints = new Point[]
            {
        new Point(customCursorPosition.X + 3, customCursorPosition.Y), // Pointe de la flèche légèrement penchée vers la gauche
        new Point(customCursorPosition.X - 12, customCursorPosition.Y - 5),
        new Point(customCursorPosition.X - 12, customCursorPosition.Y + 5)
            };

            e.Graphics.FillPolygon(Brushes.Black, arrowPoints); // Remplir le triangle avec la couleur noire
        }

        private void panel1_MouseMove(object sender, MouseEventArgs e)
        {


            if (isDragging)
            {
                // Déplacer la fenêtre si le clic de la souris est maintenu enfoncé
                windowPosition = e.Location;
                panel1.Invalidate(); // Redessiner pour afficher la fenêtre déplacée
            }

            customCursorPosition = e.Location;
            panel1.Invalidate(); // Redessiner pour afficher le curseur personnalisé
        }

        private void panel1_MouseDown(object sender, MouseEventArgs e)
        {
            // Vérifier si le clic de la souris est à l'intérieur de la fenêtre
            Rectangle windowRectangle = new Rectangle(windowPosition, windowSize);
            if (windowRectangle.Contains(e.Location))
            {
                isDragging = true; // Commencer le déplacement de la fenêtre
            }
        }

        private void panel1_MouseUp(object sender, MouseEventArgs e)
        {
            isDragging = false; // Arrêter le déplacement de la fenêtre lorsque le clic de la souris est relâché
        }

        private async void StartFakeComputer()
        {
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Hello World\n")));
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"{DateTime.Now} Démarrage en cours...\n")));

            try
            {
                Socket dhcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                // Configuration des informations DHCP pour la demande
                byte[] dhcpDiscoverPacket = BuildDhcpDiscoverPacket();

                // Définir l'adresse IP du serveur DHCP (adresse de broadcast typiquement)
                IPAddress dhcpServerIP = IPAddress.Parse("172.20.10.1");

                // Port UDP utilisé par le serveur DHCP (port 67 est souvent utilisé côté serveur)
                IPEndPoint dhcpServerEndPoint = new IPEndPoint(dhcpServerIP, 67);

                // Configuration des options de socket pour l'envoi en broadcast
                dhcpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, 1);

                // Envoyer la demande DHCP
                dhcpSocket.SendTo(dhcpDiscoverPacket, dhcpServerEndPoint);

                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"{DateTime.Now} Demande DHCPDISCOVER envoyée avec succès.\n")));

                Task responseTask = Task.Run(() => ListenForDhcpResponse());
                Task delayTask = Task.Delay(10000); // Délai de 10 secondes

                // Attendre la fin du délai ou de la réception d'une réponse DHCP
                await Task.WhenAny(responseTask, delayTask);

                if (!responseTask.IsCompleted)
                {
                    // Le délai s'est écoulé sans réponse DHCP, envoyer des paquets ARP
                    Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"{DateTime.Now} Aucune réponse DHCP reçue. Envoi de paquets ARP...\n")));

                    // Appeler une méthode pour envoyer des paquets ARP
                    SendArpPackets();
                }
            }
            catch (SocketException ex)
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Erreur de socket : {ex.Message}\n")));
            }
            catch (Exception ex)
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Erreur : {ex.Message}\n")));
            }
        }

        private void SendArpPackets()
        {
            // Envoyer des paquets ARP ici
            if (string.IsNullOrEmpty(assignedIPAddress))
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Aucune réponse du routeur. Utilisation de l'adresse IP locale à la place...\n")));

                // Obtention de l'adresse IP locale de l'ordinateur
                string localIPAddress = GetLocalIPAddress();

                if (!string.IsNullOrEmpty(localIPAddress))
                {
                    assignedIPAddress = localIPAddress;
                    UpdateAssignedIPAddressLabel();

                    // Envoi de paquets ARP comme un ordinateur normal
                    StartListening();
                    Task.Run(() => EmulateNormalComputerBehavior());
                }
                else
                {
                    Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Impossible d'obtenir l'adresse IP locale de l'ordinateur.\n")));
                }
            }
        }

        private async void StartListening()
        {
            await Task.Run(() =>
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP))
                {
                    try
                    {
                        socket.Bind(new IPEndPoint(IPAddress.Parse(assignedIPAddress), 0));

                        byte[] buffer = new byte[4096];
                        EndPoint endPoint = new IPEndPoint(IPAddress.Any, 0);

                        while (true)
                        {
                            int received = socket.ReceiveFrom(buffer, ref endPoint);
                            ParseARPPacket(buffer, received);
                        }
                    }
                    catch (SocketException ex)
                    {
                        // Gérer les exceptions
                        Invoke(new Action(() =>
                        {
                            richTextBoxLogs.AppendText($"Socket exception: {ex.Message}\n");
                        }));
                    }
                }
            });
        }

        private void ParseARPPacket(byte[] buffer, int length)
        {
            // Votre logique pour analyser et traiter les paquets ARP reçus
            // Les paquets ARP ont une structure spécifique pour l'analyse des adresses MAC et IP
            // Vous pouvez extraire les informations nécessaires à partir du buffer ici

            // Exemple de traitement : Analyse d'un paquet ARP simple

            // Vérifier si le paquet est de type ARP et a une longueur minimale
            if (length >= 28 && buffer[12] == 0x08 && buffer[13] == 0x06)
            {
            }
            else
            {
                richTextBoxLogs.Invoke(new Action(() =>
                {
                    richTextBoxLogs.AppendText($"/!\\ Received packet is not an ARP packet or does not have the expected length.\n\n");
                }));
            }
            // Adresse MAC source (6 octets)
            string sourceMAC = BitConverter.ToString(buffer, 6, 6).Replace("-", ":");
                // Adresse IP source (4 octets)
                string sourceIP = $"{buffer[14]}.{buffer[15]}.{buffer[16]}.{buffer[17]}";
                // Adresse MAC cible (6 octets)
                string destMAC = BitConverter.ToString(buffer, 18, 6).Replace("-", ":");
                // Adresse IP cible (4 octets)
                string destIP = $"{buffer[24]}.{buffer[25]}.{buffer[26]}.{buffer[27]}";

                // Loguer les informations extraites dans richTextBoxLogs
                richTextBoxLogs.Invoke(new Action(() =>
                {
                    richTextBoxLogs.AppendText($"ARP Packet Received:\n");
                    richTextBoxLogs.AppendText($"Source MAC: {sourceMAC}, Source IP: {sourceIP}\n");
                    richTextBoxLogs.AppendText($"Destination MAC: {destMAC}, Destination IP: {destIP}\n\n");
                }));
        }

        private void EmulateNormalComputerBehavior()
        {
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Emulating normal computer behavior.\n")));
            System.Threading.Timer timer = new System.Threading.Timer(SendARPRequest, null, TimeSpan.Zero, TimeSpan.FromSeconds(10));
        }

        private void SendARPRequest(object state)
        {
            string localIPAddress = GetLocalIPAddres();
            string broadcastAddress = GetBroadcastAddress(localIPAddress);
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Broadcast detected : {broadcastAddress}\n")));
            Invoke(new MethodInvoker(() => label2.Text = "Broadcast" + broadcastAddress));
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Sending EARP request : {broadcastAddress}\n")));

            if (!string.IsNullOrEmpty(broadcastAddress))
            {
                // Envoyer la requête ARP à l'adresse de diffusion
                Ping ping = new Ping();
                PingReply reply = ping.Send(broadcastAddress);

                if (reply.Status == IPStatus.Success)
                {
                    // Simulation de la réponse à la requête ARP
                    string macAddress = macadresse; // Adresse MAC simulée
                    Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Received EARP Reply from {reply.Address}: MAC Address: {macAddress}\n")));
                }
                else
                {
                    Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"No EARP Reply detected\n")));
                }
            }
            else
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Broadcast address could not be determined.\n")));
            }
        }

        private string GetLocalIPAddres()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return string.Empty;
        }

        private string GetBroadcastAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
            {
                return string.Empty;
            }

            string[] ipAddressParts = ipAddress.Split('.');
            if (ipAddressParts.Length != 4)
            {
                return string.Empty;
            }

            ipAddressParts[3] = "255"; // Modifier le dernier octet pour obtenir l'adresse de diffusion
            return string.Join(".", ipAddressParts);
        }


        private string GetLocalIPAddress()
        {
            string localIP = string.Empty;
            try
            {
                // Recherche des interfaces réseau pour obtenir l'adresse IP locale
                foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (netInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        foreach (UnicastIPAddressInformation ip in netInterface.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                localIP = ip.Address.ToString();
                                break;
                            }
                        }

                        if (!string.IsNullOrEmpty(localIP))
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                // Gestion des erreurs éventuelles lors de la récupération de l'adresse IP
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Erreur lors de la récupération de l'adresse IP locale : {ex.Message}\n")));
            }
            return localIP;
        }



        private void ListenForDhcpResponse()
        {
            byte[] buffer = new byte[1024];
            Socket dhcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            EndPoint serverEndPoint = new IPEndPoint(IPAddress.Any, 0);

            try
            {
                dhcpSocket.Bind(new IPEndPoint(IPAddress.Any, 68)); // Écoute sur le port 68 (port du client DHCP)
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"{DateTime.Now} En attente de la réponse DHCP...\n")));

                while (true)
                {
                    int received = dhcpSocket.ReceiveFrom(buffer, ref serverEndPoint);

                    // Analyser la réponse DHCP pour extraire l'adresse IP attribuée
                    string assignedIP = ParseAssignedIPAddress(buffer, received);

                    if (!string.IsNullOrEmpty(assignedIP))
                    {
                        assignedIPAddress = assignedIP;

                        // Mettre à jour le label avec l'adresse IP attribuée
                        UpdateAssignedIPAddressLabel();
                        break; // Sortir de la boucle une fois que l'adresse IP est reçue
                    }
                }
            }
            catch (SocketException ex)
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Erreur de socket : {ex.Message}\n")));
            }
            catch (Exception ex)
            {
                Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Erreur : {ex.Message}\n")));
            }
        }

        private string ParseAssignedIPAddress(byte[] buffer, int length)
        {
            // Vérifier si le paquet est un paquet DHCP
            if (buffer[240] != 0x63 || buffer[241] != 0x82 || buffer[242] != 0x53 || buffer[243] != 0x63)
            {
                return null; // Le paquet n'est pas un paquet DHCP
            }

            // Trouver l'option 50 (Requested IP Address) dans le paquet DHCP
            for (int i = 0; i < length; i++)
            {
                if (buffer[i] == 50) // Option 50 (Requested IP Address)
                {
                    // L'adresse IP attribuée commence après l'octet de longueur
                    return $"{buffer[i + 2]}.{buffer[i + 3]}.{buffer[i + 4]}.{buffer[i + 5]}";
                }
            }

            return null; // Aucune adresse IP attribuée trouvée dans le paquet
        }


        private void UpdateAssignedIPAddressLabel()
        {
            if (assignedIPAddress != null)
            {
                // Assurez-vous d'accéder à l'interface utilisateur depuis le thread principal
                if (InvokeRequired)
                {
                    Invoke(new MethodInvoker(() => labelAssignedIP.Text = "IP : " + assignedIPAddress));
                }
                else
                {
                    labelAssignedIP.Text = "IP : " + assignedIPAddress;
                }
            }
        }

        private byte[] BuildDhcpDiscoverPacket()
        {
            // Construire un paquet DHCPDISCOVER selon le format DHCP spécifique
            // Ceci est un exemple simplifié pour illustrer le concept

            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Construction du paquet DHCPDISCOVER...\n")));

            byte[] dhcpPacket = new byte[300]; // Taille du paquet DHCP à adapter selon les besoins

            // Header DHCP (exemples de champs)
            dhcpPacket[0] = 0x01; // Message Type (DHCPDISCOVER)
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Ajout du type de message DHCPDISCOVER...\n")));

            dhcpPacket[1] = 0x01; // Hardware Type (Ethernet)
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Ajout du type de matériel Ethernet...\n")));

            // Générer une adresse MAC aléatoire
            string macAddress = GenerateRandomMacAddress();
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText($"Adresse MAC générée aléatoirement : {macAddress}\n")));
            macadresse = macAddress;

            // Insérer l'adresse MAC dans le champ chaddr du paquet DHCP
            string[] macBytes = macAddress.Split(':');
            for (int i = 0; i < 6; i++)
            {
                dhcpPacket[i + 28] = Convert.ToByte(macBytes[i], 16);
            }
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Adresse MAC insérée dans le paquet DHCP...\n")));

            // Options DHCP (exemples de champs)
            // Identifier le début de la section d'options
            dhcpPacket[240] = 0x63; // Magic Cookie
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Ajout du Magic Cookie pour les options DHCP...\n")));

            // Option : DHCP Message Type
            dhcpPacket[241] = 0x35; // Option DHCP Message Type
            dhcpPacket[242] = 0x01; // Longueur de l'option
            dhcpPacket[243] = 0x01; // Valeur : DHCPDISCOVER (1)
            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Ajout de l'option DHCP Message Type DHCPDISCOVER...\n")));

            // Autres options DHCP à remplir selon les besoins...

            Invoke(new MethodInvoker(() => richTextBoxLogs.AppendText("Construction du paquet DHCPDISCOVER terminée.\n")));
            return dhcpPacket;
        }

        private string GenerateRandomMacAddress()
        {
            byte[] macAddr = new byte[6];
            Random rand = new Random();
            rand.NextBytes(macAddr);

            // Assurer que l'adresse MAC est une adresse unicast et locale
            macAddr[0] = (byte)(macAddr[0] & 0xFE);
            macAddr[0] = (byte)(macAddr[0] | 0x02);

            return string.Join(":", macAddr.Select(b => b.ToString("X2")));
        }

        private void panel1_MouseEnter(object sender, EventArgs e)
        {
            Cursor.Hide(); // Cacher le curseur par défaut
        }

        private void panel1_MouseLeave(object sender, EventArgs e)
        {
            Cursor.Show(); // Pour afficher à nouveau le curseur système
        }
    }
}

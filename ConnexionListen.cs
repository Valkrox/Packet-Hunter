using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace PacketHunter3
{
    public partial class ConnexionListen : Form
    {

        private List<TcpConnectionInformation> activeTcpConnections;
        private Image cePCImage;

        private Image ResizeImage(Image img, Size size)
        {
            return new Bitmap(img, size);
        }

        private async Task<Image> GetFaviconAsync(string websiteUrl)
        {
            try
            {
                if (checkBox1.Checked == false)
                {
                    if (websiteUrl.Equals("DESKTOP", StringComparison.OrdinalIgnoreCase) || websiteUrl.Equals("LAPTOP", StringComparison.OrdinalIgnoreCase))
                    {
                        // Chemin de l'icône de Ce PC sur Windows
                        string iconPath = @"C:\Windows\System32\imageres.dll"; // Chemin de l'icône de "Ce PC"

                        // Récupérer l'icône de Ce PC
                        Icon systemIcon = Icon.ExtractAssociatedIcon(iconPath);
                        return systemIcon.ToBitmap(); // Convertir l'icône en image
                    }
                    else
                    {
                        string faviconUrl = $"https://www.google.com/s2/favicons?domain={websiteUrl}";
                        using (HttpClient client = new HttpClient())
                        {
                            HttpResponseMessage response = await client.GetAsync(faviconUrl);
                            if (response.IsSuccessStatusCode)
                            {
                                byte[] imageData = await response.Content.ReadAsByteArrayAsync();
                                return Image.FromStream(new System.IO.MemoryStream(imageData));
                            }
                        }
                    }
                }
                else
                {

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Une erreur s'est produite lors de la récupération de l'icône : {ex.Message}");
            }
            return null;
        }

        // Méthode pour obtenir le nom de domaine à partir de l'adresse IP
        // Méthode asynchrone pour obtenir le nom de domaine à partir de l'adresse IP
        private async Task<string> GetDomainFromIPAddressAsync(string ipAddress)
        {
            try
            {
                IPHostEntry hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                return hostEntry.HostName;
            }
            catch (Exception)
            {
                return "Domaine non trouvé";
            }
        }

        // Méthode FillConnections modifiée pour afficher le nom de domaine
        private bool IsWebSite(string domain)
        {
            if (checkBox1.Checked == false)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine(DateTime.Now.ToString() + "Info : IsWebSite = false");
                Console.ForegroundColor = ConsoleColor.White;
                return false;
            }

            // Vérifie si le domaine n'est pas une adresse IP
            if (Uri.CheckHostName(domain) == UriHostNameType.IPv4 || Uri.CheckHostName(domain) == UriHostNameType.IPv6)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine(DateTime.Now.ToString() + "Info : IsWebSite = false");
                Console.ForegroundColor = ConsoleColor.White;
                return false;
            }

            // Vérifie s'il n'y a pas de caractères non autorisés dans le domaine
            string[] invalidCharacters = { ":", "/", "\\", "?", "#", "[", "]" }; // Ajoutez d'autres caractères si nécessaire
            if (invalidCharacters.Any(c => domain.Contains(c)))
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine(DateTime.Now.ToString() + "Info : IsWebSite = false");
                Console.ForegroundColor = ConsoleColor.White;
                return false;
            }

           

            // Ajoutez d'autres critères de filtrage si nécessaire

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(DateTime.Now.ToString() + "Info : IsWebSite = true");
            Console.ForegroundColor = ConsoleColor.White;
            return true;
        }

        public ConnexionListen()
        {
            InitializeComponent();

            listViewConnections.View = View.Details;

            listViewConnections.Columns.Add("Remote End Point", 150);
            listViewConnections.Columns.Add("Local End Point", 150);
            listViewConnections.Columns.Add("State", 100);
            listViewConnections.Columns.Add("Website", 150);
            listViewConnections.Columns.Add("Local Address", 150);
            listViewConnections.Columns.Add("Local Port", 100);
            listViewConnections.Columns.Add("Remote Address", 150);
            listViewConnections.Columns.Add("Remote Port", 100);

            // Créez la LargeImageList pour stocker les icônes
            listViewConnections.LargeImageList = new ImageList();

            activeTcpConnections = GetActiveTcpConnections();

            // Remplit la ListView avec les connexions actives
            FillConnectionsAsync(activeTcpConnections);
        }



        private async Task FillConnectionsAsync(List<TcpConnectionInformation> connections)
        {
            try
            {
                ImageList largeImageList = new ImageList();
                ImageList smallImageList = new ImageList();

                listViewConnections.LargeImageList = largeImageList;
                listViewConnections.SmallImageList = smallImageList;
                listViewConnections.View = View.Details;

                foreach (var connection in connections)
                {
                    string remoteEndPoint = connection.RemoteEndPoint.ToString();
                    string localEndPoint = connection.LocalEndPoint.ToString();
                    string remoteIP = remoteEndPoint.Split(':')[0]; // Obtenez l'adresse IP distante
                    string remoteDomain = await GetDomainFromIPAddressAsync(remoteIP); // Utilisez votre méthode GetDomainFromIPAddressAsync

                    string[] connectionDetails = {
                remoteEndPoint,
                localEndPoint,
                connection.State.ToString(),
                remoteDomain, // Nom de domaine
                connection.LocalEndPoint.Address.ToString(), // Adresse locale
                connection.LocalEndPoint.Port.ToString(), // Port local
                connection.RemoteEndPoint.Address.ToString(), // Adresse distante
                connection.RemoteEndPoint.Port.ToString() // Port distant
            };

                    Image imageToAdd = null;

                    if (IsWebSite(remoteDomain))
                    {
                        Image favicon = await GetFaviconAsync(remoteDomain);
                        if (favicon != null)
                        {
                            imageToAdd = favicon;
                        }
                    }
                    else
                    {
                        imageToAdd = cePCImage;
                    }

                    if (imageToAdd != null)
                    {
                        largeImageList.Images.Add(imageToAdd);
                        smallImageList.Images.Add(imageToAdd);

                        int imageIndex = largeImageList.Images.Count - 1;

                        ListViewItem item = new ListViewItem(connectionDetails, imageIndex);
                        listViewConnections.Items.Add(item);
                    }
                    else
                    {
                        ListViewItem item = new ListViewItem(connectionDetails);
                        listViewConnections.Items.Add(item);
                    }

                    if (IsWebSite(remoteDomain))
                    {
                        // Obtenez l'icône du site web (favicon) de manière asynchrone
                        Image favicon = null;
                        if (favicon != null)
                        {
                            // Ajoutez l'icône à la LargeImageList et référencez-la dans l'item
                            listViewConnections.LargeImageList.Images.Add(favicon);
                            connectionDetails[3] = ""; // L'image sera ajoutée comme icône, donc pas besoin du nom de domaine ici
                            listViewConnections.Items.Add(new ListViewItem(connectionDetails, listViewConnections.LargeImageList.Images.Count - 1));
                        }
                        else
                        {
                            // Ajoutez les détails de la connexion sans icône
                            listViewConnections.Items.Add(new ListViewItem(connectionDetails));
                        }
                    }
                    else
                    {
                        Console.WriteLine("test1");
                        listViewConnections.LargeImageList.Images.Add(cePCImage);
                        int imageIndex = listViewConnections.LargeImageList.Images.Count - 1;
                        ListViewItem item = new ListViewItem(connectionDetails, imageIndex);
                        listViewConnections.Items.Add(item);
                    }

                    label1.Text = "Nombre de connexions : " + listViewConnections.Items.Count /2;

                }

                label1.Text = "Nombre de connexions : " + listViewConnections.Items.Count.ToString();
            }
            catch (Exception ex)
            {
                LogError(ex.Message);
            }
        }






        private List<TcpConnectionInformation> GetActiveTcpConnections()
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            return ipGlobalProperties.GetActiveTcpConnections().ToList();
        }

        private void LogError(string errorMessage)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            string logMessage = $"{DateTime.Now} | Erreur : {errorMessage}";
            Console.WriteLine(logMessage);
            Console.ForegroundColor = ConsoleColor.White;
        }

        private void CloseSelectedConnection()
        {
            try
            {
                if (listViewConnections.SelectedItems.Count > 0)
                {
                    string localEndPoint = listViewConnections.SelectedItems[0].SubItems[0].Text;
                    string remoteEndPoint = listViewConnections.SelectedItems[0].SubItems[1].Text;

                    // Trouve la connexion correspondante dans la liste des connexions actives
                    TcpConnectionInformation connectionToClose = activeTcpConnections.FirstOrDefault(conn =>
                        conn.LocalEndPoint.ToString() == localEndPoint &&
                        conn.RemoteEndPoint.ToString() == remoteEndPoint);

                    if (connectionToClose != null)
                    {
                        // Ferme localement la connexion en utilisant le socket existant
                        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                        {
                            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, new LingerOption(true, 0));
                            socket.Close();
                        }

                        // Met à jour la liste des connexions actives
                        activeTcpConnections = GetActiveTcpConnections();

                        MessageBox.Show($"Connexion fermée localement : LocalEndPoint = {localEndPoint}, RemoteEndPoint = {remoteEndPoint}");
                    }
                    else
                    {
                        MessageBox.Show("Connexion non trouvée dans la liste des connexions actives.");
                    }
                }
                else
                {
                    MessageBox.Show("Aucune connexion sélectionnée.");
                }
            }
            catch (Exception ex)
            {
                LogError(ex.Message);
            }
        }




        // Méthode pour charger l'image de "Ce PC"
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int PrivateExtractIcons(string lpszFile, int nIconIndex, int cxIcon, int cyIcon, IntPtr[] phicon, IntPtr[] piconid, uint nIcons, uint flags);

        private void LoadCePCImage()
        {
            try
            {
                string iconPath = @"C:\Windows\System32\imageres.dll"; // Chemin de l'icône de "Ce PC"

                const int iconIndex = 20; // Index de l'icône de "Ce PC" dans la DLL

                IntPtr[] phicon = new IntPtr[1];

                // Appel de la méthode PrivateExtractIcons pour extraire l'icône spécifique
                int result = PrivateExtractIcons(iconPath, iconIndex, 32, 32, phicon, null, 1, 0x00000001);

                if (result > 0)
                {
                    Icon systemIcon = Icon.FromHandle(phicon[0]);
                    cePCImage = systemIcon.ToBitmap();
                }
                else
                {
                    Console.WriteLine("L'icône de 'Ce PC' n'a pas pu être extraite.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Une erreur s'est produite lors du chargement de l'icône de 'Ce PC': {ex.Message}");
            }
        }


        private void ConnexionListen_Load(object sender, EventArgs e)
        {
            LoadCePCImage();

            if (cePCImage != null)
            {
                // Créez votre ImageList
                ImageList largeImageList = new ImageList();
                largeImageList.ImageSize = new Size(64, 64); // Définissez la taille souhaitée (par exemple 64x64 pour le mode LargeIcon)

                // Redimensionnez votre image
                Image resizedImage = ResizeImage(cePCImage, largeImageList.ImageSize);

                // Ajoutez l'image redimensionnée à l'ImageList
                largeImageList.Images.Add(resizedImage);

                // Associez l'ImageList à votre ListView
                listViewConnections.LargeImageList = largeImageList;

                // Ajoutez un élément avec l'image à la ListView
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            CloseSelectedConnection();
            listViewConnections.Items.Clear();
            activeTcpConnections = GetActiveTcpConnections();
            FillConnectionsAsync(activeTcpConnections);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            listViewConnections.Items.Clear();
            activeTcpConnections = GetActiveTcpConnections();
            FillConnectionsAsync(activeTcpConnections);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if(listViewConnections.View == View.Details) 
            {
                listViewConnections.View = View.LargeIcon;
                button3.Text = "LargeIcon";
                return;
            }
            else
            {
                listViewConnections.View = View.Details;
                button3.Text = "Details";
                return;
            }
        }
    }
}

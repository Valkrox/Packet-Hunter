using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PacketHunter3
{
    public partial class Main : Form
    {

        private bool isResizing = false;
        private Point resizeStart;
        private bool isDraggingTextBox = false;
        private Point textBoxOffset;
        private int resizeBorderWidth = 8; // Largeur de la zone de redimensionnement
        private bool resizing = false;
        private Color Default = Color.White;


        private Point startPoint;
        private bool drag = false;
        private int m_opacity = 100;
        Form1 form1Instance = new Form1();

        private int alpha;
        private int originalLeft;
        private int originalTop;
        private int originalWidth;
        private int originalHeight;
        private bool isFullScreen;
        public Main()
        {
            InitializeComponent();

            // Obtenez l'icône de la fenêtre
            Icon windowIcon = this.Icon;

            // Convertissez l'icône en une image
            Image windowImage = windowIcon.ToBitmap();

            // Définissez l'image comme arrière-plan du Panel14
            Panel14.BackgroundImage = windowImage;

            // Créez un chemin pour les coins légèrement arrondis
            int radius = 10; // Réglez le rayon des coins légèrement arrondis ici

            GraphicsPath path = new GraphicsPath();

            // Coin supérieur gauche
            path.AddArc(new Rectangle(0, 0, 2 * radius, 2 * radius), 180, 90);

            // Coin supérieur droit
            path.AddArc(new Rectangle(Width - 2 * radius, 0, 2 * radius, 2 * radius), 270, 90);

            // Coin inférieur droit
            path.AddArc(new Rectangle(Width - 2 * radius, Height - 2 * radius, 2 * radius, 2 * radius), 0, 90);

            // Coin inférieur gauche
            path.AddArc(new Rectangle(0, Height - 2 * radius, 2 * radius, 2 * radius), 90, 90);

            // Fermez le chemin
            path.CloseAllFigures();

            // Appliquez la région au formulaire
            Region = new Region(path);
        }

        private void Main_Load(object sender, EventArgs e)
        {
            // Supposons que tu aies déjà une instance de Form1 nommée form1Instance
            
            
            form1Instance.TopLevel = false;
            form1Instance.FormBorderStyle = FormBorderStyle.None; // Optionnel, pour masquer le cadre de la Form si nécessaire

            // Définition du parent de form1Instance sur le Panel
            form1Instance.Parent = panelContainer;

            // Redimensionnement de form1Instance pour correspondre à la taille du Panel
            form1Instance.Size = panelContainer.Size;

            // Positionnement éventuel de form1Instance à l'intérieur du Panel
            form1Instance.Location = new Point(0, 0); // Position de départ au coin supérieur gauche du Panel

            // Affichage de form1Instance
            form1Instance.Show();

        }

        private void Label18_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void Label18_Enter(object sender, EventArgs e)
        {
            Label18.ForeColor = Color.Red;
        }

        private void Label18_Leave(object sender, EventArgs e)
        {
            Label18.ForeColor = Color.White;
        }

        private void Label19_MouseEnter(object sender, EventArgs e)
        {
            Label19.ForeColor = Color.Blue;
        }

        private void Label19_MouseLeave(object sender, EventArgs e)
        {
            Label19.ForeColor = Color.White;
        }

        private void Label20_MouseEnter(object sender, EventArgs e)
        {
            Label20.ForeColor = Color.Blue;
        }

        private void Label20_MouseLeave(object sender, EventArgs e)
        {
            Label20.ForeColor = Color.White;
        }

        private void Label19_Click(object sender, EventArgs e)
        {
            if (!isFullScreen)
            {
                originalLeft = this.Left;
                originalTop = this.Top;
                originalWidth = this.Width;
                originalHeight = this.Height;
                this.Region = null;
                ControlBox = false;
                this.Left = -7;
                this.Top = 0;
                this.Width = Screen.PrimaryScreen.WorkingArea.Width + 5;
                this.Height = Screen.PrimaryScreen.WorkingArea.Height + 7;
                isFullScreen = true;

            }
            else
            {

                this.Left = originalLeft;
                this.Top = originalTop;
                this.Width = originalWidth;
                this.Height = originalHeight;

                int radius = 10; // Réglez le rayon des coins légèrement arrondis ici

                GraphicsPath path = new GraphicsPath();

                // Coin supérieur gauche
                path.AddArc(new Rectangle(0, 0, 2 * radius, 2 * radius), 180, 90);

                // Coin supérieur droit
                path.AddArc(new Rectangle(Width - 2 * radius, 0, 2 * radius, 2 * radius), 270, 90);

                // Coin inférieur droit
                path.AddArc(new Rectangle(Width - 2 * radius, Height - 2 * radius, 2 * radius, 2 * radius), 0, 90);

                // Coin inférieur gauche
                path.AddArc(new Rectangle(0, Height - 2 * radius, 2 * radius, 2 * radius), 90, 90);

                // Fermez le chemin
                path.CloseAllFigures();

                // Appliquez la région au formulaire
                Region = new Region(path);
                isFullScreen = false;
            }
        }

        private void Label20_Click(object sender, EventArgs e)
        {
            this.WindowState = FormWindowState.Minimized;
        }

        private void Label18_MouseEnter(object sender, EventArgs e)
        {
            Label18.ForeColor = Color.Red;
        }

        private void Label18_MouseLeave(object sender, EventArgs e)
        {
            Label18.ForeColor = Color.White;
        }

        private void Main_Resize(object sender, EventArgs e)
        {
            form1Instance.Size = new Size(panel1.Width, panel1.Height);
            form1Instance.Location = new Point(form1Instance.Location.X, form1Instance.Location.Y /2);
        }
    }
}

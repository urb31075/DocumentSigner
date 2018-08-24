namespace MyPGP
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.PGPButton = new System.Windows.Forms.Button();
            this.InfoListBox = new System.Windows.Forms.ListBox();
            this.SuspendLayout();
            // 
            // PGPButton
            // 
            this.PGPButton.Location = new System.Drawing.Point(12, 12);
            this.PGPButton.Name = "PGPButton";
            this.PGPButton.Size = new System.Drawing.Size(75, 23);
            this.PGPButton.TabIndex = 0;
            this.PGPButton.Text = "PGP";
            this.PGPButton.UseVisualStyleBackColor = true;
            this.PGPButton.Click += new System.EventHandler(this.PgpButtonClick);
            // 
            // InfoListBox
            // 
            this.InfoListBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.InfoListBox.FormattingEnabled = true;
            this.InfoListBox.Location = new System.Drawing.Point(102, 12);
            this.InfoListBox.Name = "InfoListBox";
            this.InfoListBox.Size = new System.Drawing.Size(805, 238);
            this.InfoListBox.TabIndex = 1;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(919, 261);
            this.Controls.Add(this.InfoListBox);
            this.Controls.Add(this.PGPButton);
            this.Name = "MainForm";
            this.Text = "MyPGP";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button PGPButton;
        private System.Windows.Forms.ListBox InfoListBox;
    }
}


namespace DocumentSigner
{
    partial class DocumentSugnerForm
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
            this.InfoListBox = new System.Windows.Forms.ListBox();
            this.VerifySignatureOnlyCheckBox = new System.Windows.Forms.CheckBox();
            this.ImportCertificateButton = new System.Windows.Forms.Button();
            this.CreateMiniDumpButton = new System.Windows.Forms.Button();
            this.GenerateKeyPairButton = new System.Windows.Forms.Button();
            this.EncryptButton = new System.Windows.Forms.Button();
            this.ExtractButton = new System.Windows.Forms.Button();
            this.DecryptButton = new System.Windows.Forms.Button();
            this.HashButton = new System.Windows.Forms.Button();
            this.BouncyCastleButton = new System.Windows.Forms.Button();
            this.CheckAtachedButton = new System.Windows.Forms.Button();
            this.SignAtachedButton = new System.Windows.Forms.Button();
            this.AddContextMenuButton = new System.Windows.Forms.Button();
            this.RemoveContextMenuButton = new System.Windows.Forms.Button();
            this.ListDirButton = new System.Windows.Forms.Button();
            this.CreateRequestButton = new System.Windows.Forms.Button();
            this.CertificatesComboBox = new System.Windows.Forms.ComboBox();
            this.FileForSignNameTextBox = new System.Windows.Forms.TextBox();
            this.FileNameButton = new System.Windows.Forms.Button();
            this.RemoveCertificateButton = new System.Windows.Forms.Button();
            this.CertificateGroupBox = new System.Windows.Forms.GroupBox();
            this.CertificateListBox = new System.Windows.Forms.ListBox();
            this.SignGroupBox = new System.Windows.Forms.GroupBox();
            this.AssuteSignButton = new System.Windows.Forms.Button();
            this.CheckGroupBox = new System.Windows.Forms.GroupBox();
            this.ExtractDocumentButton = new System.Windows.Forms.Button();
            this.FileForCheckNameTextBox = new System.Windows.Forms.TextBox();
            this.button2 = new System.Windows.Forms.Button();
            this.MainTabControl = new System.Windows.Forms.TabControl();
            this.SignTabPage = new System.Windows.Forms.TabPage();
            this.OptionsTabPage = new System.Windows.Forms.TabPage();
            this.DebugTabPage = new System.Windows.Forms.TabPage();
            this.CertificateGroupBox.SuspendLayout();
            this.SignGroupBox.SuspendLayout();
            this.CheckGroupBox.SuspendLayout();
            this.MainTabControl.SuspendLayout();
            this.SignTabPage.SuspendLayout();
            this.OptionsTabPage.SuspendLayout();
            this.DebugTabPage.SuspendLayout();
            this.SuspendLayout();
            // 
            // InfoListBox
            // 
            this.InfoListBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.InfoListBox.FormattingEnabled = true;
            this.InfoListBox.HorizontalScrollbar = true;
            this.InfoListBox.Location = new System.Drawing.Point(6, 83);
            this.InfoListBox.Name = "InfoListBox";
            this.InfoListBox.ScrollAlwaysVisible = true;
            this.InfoListBox.Size = new System.Drawing.Size(641, 264);
            this.InfoListBox.TabIndex = 3;
            // 
            // VerifySignatureOnlyCheckBox
            // 
            this.VerifySignatureOnlyCheckBox.AutoSize = true;
            this.VerifySignatureOnlyCheckBox.Checked = true;
            this.VerifySignatureOnlyCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.VerifySignatureOnlyCheckBox.Location = new System.Drawing.Point(6, 52);
            this.VerifySignatureOnlyCheckBox.Name = "VerifySignatureOnlyCheckBox";
            this.VerifySignatureOnlyCheckBox.Size = new System.Drawing.Size(172, 17);
            this.VerifySignatureOnlyCheckBox.TabIndex = 5;
            this.VerifySignatureOnlyCheckBox.Text = "Проверять только сигнатуру";
            this.VerifySignatureOnlyCheckBox.UseVisualStyleBackColor = true;
            // 
            // ImportCertificateButton
            // 
            this.ImportCertificateButton.Location = new System.Drawing.Point(118, 19);
            this.ImportCertificateButton.Name = "ImportCertificateButton";
            this.ImportCertificateButton.Size = new System.Drawing.Size(106, 23);
            this.ImportCertificateButton.TabIndex = 6;
            this.ImportCertificateButton.Text = "Импорт из файла";
            this.ImportCertificateButton.UseVisualStyleBackColor = true;
            this.ImportCertificateButton.Click += new System.EventHandler(this.ImportCertificateButtonClick);
            // 
            // CreateMiniDumpButton
            // 
            this.CreateMiniDumpButton.Location = new System.Drawing.Point(6, 6);
            this.CreateMiniDumpButton.Name = "CreateMiniDumpButton";
            this.CreateMiniDumpButton.Size = new System.Drawing.Size(149, 23);
            this.CreateMiniDumpButton.TabIndex = 7;
            this.CreateMiniDumpButton.Text = "CreateMiniDumpButton";
            this.CreateMiniDumpButton.UseVisualStyleBackColor = true;
            this.CreateMiniDumpButton.Click += new System.EventHandler(this.CreateMiniDumpButtonClick);
            // 
            // GenerateKeyPairButton
            // 
            this.GenerateKeyPairButton.Location = new System.Drawing.Point(6, 49);
            this.GenerateKeyPairButton.Name = "GenerateKeyPairButton";
            this.GenerateKeyPairButton.Size = new System.Drawing.Size(149, 23);
            this.GenerateKeyPairButton.TabIndex = 8;
            this.GenerateKeyPairButton.Text = "GenerateKeyPair";
            this.GenerateKeyPairButton.UseVisualStyleBackColor = true;
            this.GenerateKeyPairButton.Click += new System.EventHandler(this.GenerateKeyPairButtonClick);
            // 
            // EncryptButton
            // 
            this.EncryptButton.Location = new System.Drawing.Point(6, 78);
            this.EncryptButton.Name = "EncryptButton";
            this.EncryptButton.Size = new System.Drawing.Size(149, 23);
            this.EncryptButton.TabIndex = 9;
            this.EncryptButton.Text = "Encrypt";
            this.EncryptButton.UseVisualStyleBackColor = true;
            this.EncryptButton.Click += new System.EventHandler(this.EncryptButtonClick);
            // 
            // ExtractButton
            // 
            this.ExtractButton.Location = new System.Drawing.Point(6, 165);
            this.ExtractButton.Name = "ExtractButton";
            this.ExtractButton.Size = new System.Drawing.Size(149, 23);
            this.ExtractButton.TabIndex = 10;
            this.ExtractButton.Text = "Extract";
            this.ExtractButton.UseVisualStyleBackColor = true;
            this.ExtractButton.Click += new System.EventHandler(this.ExtractButtonClick);
            // 
            // DecryptButton
            // 
            this.DecryptButton.Location = new System.Drawing.Point(6, 107);
            this.DecryptButton.Name = "DecryptButton";
            this.DecryptButton.Size = new System.Drawing.Size(149, 23);
            this.DecryptButton.TabIndex = 11;
            this.DecryptButton.Text = "Decrypt";
            this.DecryptButton.UseVisualStyleBackColor = true;
            this.DecryptButton.Click += new System.EventHandler(this.DecryptButtonClick);
            // 
            // HashButton
            // 
            this.HashButton.Location = new System.Drawing.Point(6, 136);
            this.HashButton.Name = "HashButton";
            this.HashButton.Size = new System.Drawing.Size(149, 23);
            this.HashButton.TabIndex = 12;
            this.HashButton.Text = "Hash";
            this.HashButton.UseVisualStyleBackColor = true;
            this.HashButton.Click += new System.EventHandler(this.HashButtonClick);
            // 
            // BouncyCastleButton
            // 
            this.BouncyCastleButton.Location = new System.Drawing.Point(6, 218);
            this.BouncyCastleButton.Name = "BouncyCastleButton";
            this.BouncyCastleButton.Size = new System.Drawing.Size(149, 23);
            this.BouncyCastleButton.TabIndex = 13;
            this.BouncyCastleButton.Text = "BouncyCastle";
            this.BouncyCastleButton.UseVisualStyleBackColor = true;
            this.BouncyCastleButton.Click += new System.EventHandler(this.BouncyCastleButtonClick);
            // 
            // CheckAtachedButton
            // 
            this.CheckAtachedButton.Location = new System.Drawing.Point(188, 48);
            this.CheckAtachedButton.Name = "CheckAtachedButton";
            this.CheckAtachedButton.Size = new System.Drawing.Size(135, 23);
            this.CheckAtachedButton.TabIndex = 15;
            this.CheckAtachedButton.Text = "Проверить подпись";
            this.CheckAtachedButton.UseVisualStyleBackColor = true;
            this.CheckAtachedButton.Click += new System.EventHandler(this.CheckAtachedButtonClick);
            // 
            // SignAtachedButton
            // 
            this.SignAtachedButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.SignAtachedButton.Location = new System.Drawing.Point(305, 44);
            this.SignAtachedButton.Name = "SignAtachedButton";
            this.SignAtachedButton.Size = new System.Drawing.Size(182, 23);
            this.SignAtachedButton.TabIndex = 16;
            this.SignAtachedButton.Text = "Подписать / Добавить подпись";
            this.SignAtachedButton.UseVisualStyleBackColor = true;
            this.SignAtachedButton.Click += new System.EventHandler(this.SignAtachedButtonClick);
            // 
            // AddContextMenuButton
            // 
            this.AddContextMenuButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.AddContextMenuButton.Location = new System.Drawing.Point(6, 176);
            this.AddContextMenuButton.Name = "AddContextMenuButton";
            this.AddContextMenuButton.Size = new System.Drawing.Size(184, 23);
            this.AddContextMenuButton.TabIndex = 17;
            this.AddContextMenuButton.Text = "Добавить в контектное меню";
            this.AddContextMenuButton.UseVisualStyleBackColor = true;
            this.AddContextMenuButton.Click += new System.EventHandler(this.AddContextMenuButtonClick);
            // 
            // RemoveContextMenuButton
            // 
            this.RemoveContextMenuButton.Location = new System.Drawing.Point(196, 176);
            this.RemoveContextMenuButton.Name = "RemoveContextMenuButton";
            this.RemoveContextMenuButton.Size = new System.Drawing.Size(184, 23);
            this.RemoveContextMenuButton.TabIndex = 18;
            this.RemoveContextMenuButton.Text = "Удалить из контекстного меню";
            this.RemoveContextMenuButton.UseVisualStyleBackColor = true;
            this.RemoveContextMenuButton.Click += new System.EventHandler(this.RemoveContextMenuButtonClick);
            // 
            // ListDirButton
            // 
            this.ListDirButton.Location = new System.Drawing.Point(6, 305);
            this.ListDirButton.Name = "ListDirButton";
            this.ListDirButton.Size = new System.Drawing.Size(149, 23);
            this.ListDirButton.TabIndex = 19;
            this.ListDirButton.Text = "ListDirButton";
            this.ListDirButton.UseVisualStyleBackColor = true;
            this.ListDirButton.Click += new System.EventHandler(this.ListDirButtonClick);
            // 
            // CreateRequestButton
            // 
            this.CreateRequestButton.Location = new System.Drawing.Point(6, 19);
            this.CreateRequestButton.Name = "CreateRequestButton";
            this.CreateRequestButton.Size = new System.Drawing.Size(106, 23);
            this.CreateRequestButton.TabIndex = 25;
            this.CreateRequestButton.Text = "Запросить из AD";
            this.CreateRequestButton.UseVisualStyleBackColor = true;
            this.CreateRequestButton.Click += new System.EventHandler(this.CreateRequestButtonClick);
            // 
            // CertificatesComboBox
            // 
            this.CertificatesComboBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.CertificatesComboBox.FormattingEnabled = true;
            this.CertificatesComboBox.Location = new System.Drawing.Point(6, 45);
            this.CertificatesComboBox.Name = "CertificatesComboBox";
            this.CertificatesComboBox.Size = new System.Drawing.Size(293, 21);
            this.CertificatesComboBox.TabIndex = 26;
            // 
            // FileForSignNameTextBox
            // 
            this.FileForSignNameTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.FileForSignNameTextBox.Location = new System.Drawing.Point(6, 19);
            this.FileForSignNameTextBox.Name = "FileForSignNameTextBox";
            this.FileForSignNameTextBox.ReadOnly = true;
            this.FileForSignNameTextBox.Size = new System.Drawing.Size(607, 20);
            this.FileForSignNameTextBox.TabIndex = 27;
            // 
            // FileNameButton
            // 
            this.FileNameButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.FileNameButton.Location = new System.Drawing.Point(619, 19);
            this.FileNameButton.Name = "FileNameButton";
            this.FileNameButton.Size = new System.Drawing.Size(28, 20);
            this.FileNameButton.TabIndex = 28;
            this.FileNameButton.Text = "...";
            this.FileNameButton.UseVisualStyleBackColor = true;
            this.FileNameButton.Click += new System.EventHandler(this.FileForSignNameButtonClick);
            // 
            // RemoveCertificateButton
            // 
            this.RemoveCertificateButton.Location = new System.Drawing.Point(230, 19);
            this.RemoveCertificateButton.Name = "RemoveCertificateButton";
            this.RemoveCertificateButton.Size = new System.Drawing.Size(106, 23);
            this.RemoveCertificateButton.TabIndex = 29;
            this.RemoveCertificateButton.Text = "Удалить";
            this.RemoveCertificateButton.UseVisualStyleBackColor = true;
            this.RemoveCertificateButton.Click += new System.EventHandler(this.RemoveCertificateButtonClick);
            // 
            // CertificateGroupBox
            // 
            this.CertificateGroupBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.CertificateGroupBox.Controls.Add(this.CertificateListBox);
            this.CertificateGroupBox.Controls.Add(this.RemoveCertificateButton);
            this.CertificateGroupBox.Controls.Add(this.CreateRequestButton);
            this.CertificateGroupBox.Controls.Add(this.ImportCertificateButton);
            this.CertificateGroupBox.Location = new System.Drawing.Point(6, 9);
            this.CertificateGroupBox.Name = "CertificateGroupBox";
            this.CertificateGroupBox.Size = new System.Drawing.Size(653, 161);
            this.CertificateGroupBox.TabIndex = 30;
            this.CertificateGroupBox.TabStop = false;
            this.CertificateGroupBox.Text = "Сертификаты";
            // 
            // CertificateListBox
            // 
            this.CertificateListBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.CertificateListBox.FormattingEnabled = true;
            this.CertificateListBox.Location = new System.Drawing.Point(6, 48);
            this.CertificateListBox.Name = "CertificateListBox";
            this.CertificateListBox.Size = new System.Drawing.Size(641, 108);
            this.CertificateListBox.TabIndex = 0;
            // 
            // SignGroupBox
            // 
            this.SignGroupBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.SignGroupBox.Controls.Add(this.AssuteSignButton);
            this.SignGroupBox.Controls.Add(this.FileForSignNameTextBox);
            this.SignGroupBox.Controls.Add(this.FileNameButton);
            this.SignGroupBox.Controls.Add(this.CertificatesComboBox);
            this.SignGroupBox.Controls.Add(this.SignAtachedButton);
            this.SignGroupBox.Location = new System.Drawing.Point(6, 6);
            this.SignGroupBox.Name = "SignGroupBox";
            this.SignGroupBox.Size = new System.Drawing.Size(653, 78);
            this.SignGroupBox.TabIndex = 31;
            this.SignGroupBox.TabStop = false;
            this.SignGroupBox.Text = "Подписать / Добавить подпись";
            // 
            // AssuteSignButton
            // 
            this.AssuteSignButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.AssuteSignButton.Location = new System.Drawing.Point(493, 44);
            this.AssuteSignButton.Name = "AssuteSignButton";
            this.AssuteSignButton.Size = new System.Drawing.Size(154, 23);
            this.AssuteSignButton.TabIndex = 29;
            this.AssuteSignButton.Text = "Заверить подпись(и)";
            this.AssuteSignButton.UseVisualStyleBackColor = true;
            this.AssuteSignButton.Click += new System.EventHandler(this.AssuteSignButtonClick);
            // 
            // CheckGroupBox
            // 
            this.CheckGroupBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.CheckGroupBox.Controls.Add(this.ExtractDocumentButton);
            this.CheckGroupBox.Controls.Add(this.FileForCheckNameTextBox);
            this.CheckGroupBox.Controls.Add(this.button2);
            this.CheckGroupBox.Controls.Add(this.VerifySignatureOnlyCheckBox);
            this.CheckGroupBox.Controls.Add(this.CheckAtachedButton);
            this.CheckGroupBox.Controls.Add(this.InfoListBox);
            this.CheckGroupBox.Location = new System.Drawing.Point(6, 90);
            this.CheckGroupBox.Name = "CheckGroupBox";
            this.CheckGroupBox.Size = new System.Drawing.Size(653, 355);
            this.CheckGroupBox.TabIndex = 32;
            this.CheckGroupBox.TabStop = false;
            this.CheckGroupBox.Text = "Проверить подпись";
            // 
            // ExtractDocumentButton
            // 
            this.ExtractDocumentButton.Location = new System.Drawing.Point(329, 48);
            this.ExtractDocumentButton.Name = "ExtractDocumentButton";
            this.ExtractDocumentButton.Size = new System.Drawing.Size(122, 23);
            this.ExtractDocumentButton.TabIndex = 31;
            this.ExtractDocumentButton.Text = "Извлечь документ";
            this.ExtractDocumentButton.UseVisualStyleBackColor = true;
            this.ExtractDocumentButton.Click += new System.EventHandler(this.ExtractDocumentButtonClick);
            // 
            // FileForCheckNameTextBox
            // 
            this.FileForCheckNameTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.FileForCheckNameTextBox.Location = new System.Drawing.Point(6, 19);
            this.FileForCheckNameTextBox.Name = "FileForCheckNameTextBox";
            this.FileForCheckNameTextBox.ReadOnly = true;
            this.FileForCheckNameTextBox.Size = new System.Drawing.Size(607, 20);
            this.FileForCheckNameTextBox.TabIndex = 29;
            // 
            // button2
            // 
            this.button2.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.button2.Location = new System.Drawing.Point(619, 19);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(28, 20);
            this.button2.TabIndex = 30;
            this.button2.Text = "...";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.FileForCheckNameClick);
            // 
            // MainTabControl
            // 
            this.MainTabControl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.MainTabControl.Controls.Add(this.SignTabPage);
            this.MainTabControl.Controls.Add(this.OptionsTabPage);
            this.MainTabControl.Controls.Add(this.DebugTabPage);
            this.MainTabControl.Location = new System.Drawing.Point(12, 12);
            this.MainTabControl.Name = "MainTabControl";
            this.MainTabControl.SelectedIndex = 0;
            this.MainTabControl.Size = new System.Drawing.Size(673, 477);
            this.MainTabControl.TabIndex = 33;
            // 
            // SignTabPage
            // 
            this.SignTabPage.Controls.Add(this.SignGroupBox);
            this.SignTabPage.Controls.Add(this.CheckGroupBox);
            this.SignTabPage.Location = new System.Drawing.Point(4, 22);
            this.SignTabPage.Name = "SignTabPage";
            this.SignTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.SignTabPage.Size = new System.Drawing.Size(665, 451);
            this.SignTabPage.TabIndex = 0;
            this.SignTabPage.Text = "Подпись";
            this.SignTabPage.UseVisualStyleBackColor = true;
            // 
            // OptionsTabPage
            // 
            this.OptionsTabPage.Controls.Add(this.CertificateGroupBox);
            this.OptionsTabPage.Controls.Add(this.AddContextMenuButton);
            this.OptionsTabPage.Controls.Add(this.RemoveContextMenuButton);
            this.OptionsTabPage.Location = new System.Drawing.Point(4, 22);
            this.OptionsTabPage.Name = "OptionsTabPage";
            this.OptionsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.OptionsTabPage.Size = new System.Drawing.Size(665, 451);
            this.OptionsTabPage.TabIndex = 1;
            this.OptionsTabPage.Text = "Настройки";
            this.OptionsTabPage.UseVisualStyleBackColor = true;
            // 
            // DebugTabPage
            // 
            this.DebugTabPage.Controls.Add(this.CreateMiniDumpButton);
            this.DebugTabPage.Controls.Add(this.ListDirButton);
            this.DebugTabPage.Controls.Add(this.GenerateKeyPairButton);
            this.DebugTabPage.Controls.Add(this.EncryptButton);
            this.DebugTabPage.Controls.Add(this.BouncyCastleButton);
            this.DebugTabPage.Controls.Add(this.ExtractButton);
            this.DebugTabPage.Controls.Add(this.HashButton);
            this.DebugTabPage.Controls.Add(this.DecryptButton);
            this.DebugTabPage.Location = new System.Drawing.Point(4, 22);
            this.DebugTabPage.Name = "DebugTabPage";
            this.DebugTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.DebugTabPage.Size = new System.Drawing.Size(665, 451);
            this.DebugTabPage.TabIndex = 2;
            this.DebugTabPage.Text = "Отладка";
            this.DebugTabPage.UseVisualStyleBackColor = true;
            // 
            // DocumentSugnerForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(697, 501);
            this.Controls.Add(this.MainTabControl);
            this.Name = "DocumentSugnerForm";
            this.Text = "Подпись документа";
            this.Load += new System.EventHandler(this.GpiDocumentSugnerFormLoad);
            this.CertificateGroupBox.ResumeLayout(false);
            this.SignGroupBox.ResumeLayout(false);
            this.SignGroupBox.PerformLayout();
            this.CheckGroupBox.ResumeLayout(false);
            this.CheckGroupBox.PerformLayout();
            this.MainTabControl.ResumeLayout(false);
            this.SignTabPage.ResumeLayout(false);
            this.OptionsTabPage.ResumeLayout(false);
            this.DebugTabPage.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.ListBox InfoListBox;
        private System.Windows.Forms.CheckBox VerifySignatureOnlyCheckBox;
        private System.Windows.Forms.Button ImportCertificateButton;
        private System.Windows.Forms.Button CreateMiniDumpButton;
        private System.Windows.Forms.Button GenerateKeyPairButton;
        private System.Windows.Forms.Button EncryptButton;
        private System.Windows.Forms.Button ExtractButton;
        private System.Windows.Forms.Button DecryptButton;
        private System.Windows.Forms.Button HashButton;
        private System.Windows.Forms.Button BouncyCastleButton;
        private System.Windows.Forms.Button CheckAtachedButton;
        private System.Windows.Forms.Button SignAtachedButton;
        private System.Windows.Forms.Button AddContextMenuButton;
        private System.Windows.Forms.Button RemoveContextMenuButton;
        private System.Windows.Forms.Button ListDirButton;
        private System.Windows.Forms.Button CreateRequestButton;
        private System.Windows.Forms.ComboBox CertificatesComboBox;
        private System.Windows.Forms.TextBox FileForSignNameTextBox;
        private System.Windows.Forms.Button FileNameButton;
        private System.Windows.Forms.Button RemoveCertificateButton;
        private System.Windows.Forms.GroupBox CertificateGroupBox;
        private System.Windows.Forms.ListBox CertificateListBox;
        private System.Windows.Forms.GroupBox SignGroupBox;
        private System.Windows.Forms.GroupBox CheckGroupBox;
        private System.Windows.Forms.TextBox FileForCheckNameTextBox;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.Button ExtractDocumentButton;
        private System.Windows.Forms.TabControl MainTabControl;
        private System.Windows.Forms.TabPage SignTabPage;
        private System.Windows.Forms.TabPage OptionsTabPage;
        private System.Windows.Forms.TabPage DebugTabPage;
        private System.Windows.Forms.Button AssuteSignButton;
    }
}


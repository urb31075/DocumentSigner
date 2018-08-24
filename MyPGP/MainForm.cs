// --------------------------------------------------------------------------------------------------------------------
// <copyright file="MainForm.cs" company="urb31075">
// All Right Reserved  
// </copyright>
// <summary>
//   The main form.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace MyPGP
{
    using System;
    using System.IO;
    using System.Windows.Forms;

    using PGPSnippet.Keys;
    using PGPSnippet.PGPDecryption;
    using PGPSnippet.PGPEncryption;

    /// <summary>
    /// The main form.
    /// </summary>
    public partial class MainForm : Form
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MainForm"/> class.
        /// </summary>
        public MainForm()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// The pgp button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void PgpButtonClick(object sender, EventArgs e)
        {
            try
            {
                this.KeyGeneration();
                this.Encryption();
                this.Decryption();
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
                Console.Read();
            } 
        }

        /// <summary>
        /// The key generation.
        /// </summary>
        private void KeyGeneration()
        {
            #region PublicKey and Private Key Generation

            PGPSnippet.KeyGeneration.KeysForPgpEncryptionDecryption.GenerateKey("maruthi", "P@ll@m@lli", @"D:\Keys\");
            this.InfoListBox.Items.Add("Keys Generated Successfully");

            #endregion
        }

        /// <summary>
        /// The encryption.
        /// </summary>
        private void Encryption()
        {
            #region PGP Encryption

            var encryptionKeys = new PgpEncryptionKeys(@"D:\Keys\PGPPublicKey.asc", @"D:\Keys\PGPPrivateKey.asc", "P@ll@m@lli");
            var encrypter = new PgpEncrypt(encryptionKeys);
            using (Stream outputStream = File.Create(@"D:\Keys\EncryptData.txt"))
            {
                encrypter.EncryptAndSign(outputStream, new FileInfo(@"D:\Keys\PlainText.txt"));
            }

            this.InfoListBox.Items.Add("Encryption Done !");

            #endregion
        }

        /// <summary>
        /// The decryption.
        /// </summary>
        private void Decryption()
        {

            #region PGP Decryption

            PGPDecrypt.Decrypt(@"D:\Keys\EncryptData.txt", @"D:\Keys\PGPPrivateKey.asc", @"P@ll@m@lli", @"D:\Keys\OriginalText.txt");
            this.InfoListBox.Items.Add("Decryption Done");

            #endregion
        } 
    }
}


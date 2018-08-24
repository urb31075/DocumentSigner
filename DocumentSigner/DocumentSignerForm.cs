// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DocumentSugnerForm.cs" company="urb31075">
// All Right Reserved  
// </copyright>
// <summary>
//   Defines the GPIDocumentSugnerForm type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace DocumentSigner
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Pkcs;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Windows.Forms;

    using GpiCryptographic;

    using Microsoft.Win32;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;

    //using CERTCLIENTLib;

    /// <summary>
    /// The gpi document sugner form.
    /// </summary>
    public partial class DocumentSugnerForm : Form
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DocumentSugnerForm"/> class.
        /// </summary>
        public DocumentSugnerForm()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// The check.
        /// </summary>
        /// <param name="signature">
        /// The signature.
        /// </param>
        /// <param name="message">
        /// The message.
        /// </param>
        /// <param name="verifySignatureOnly">
        /// The verify signature only.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public bool Check(byte[] signature, byte[] message, bool verifySignatureOnly = false)
        {
            try
            {
                var contentInfo = new ContentInfo(message);
                var signedCms = new SignedCms(contentInfo, true); // образом сообщение не будет включено в SignedCms.
                signedCms.Decode(signature);
                if (signedCms.Certificates.Count > 0)
                {
                    var count = 1;
                    foreach (var cer in signedCms.Certificates)
                    {
                        this.InfoListBox.Items.Add($"Сертификат {count++} ");
                        this.InfoListBox.Items.Add(cer.SerialNumber ?? string.Empty);
                        this.InfoListBox.Items.Add("IssuerName: " + cer.IssuerName.Name);
                        this.InfoListBox.Items.Add("SubjectName: " + cer.SubjectName.Name);
                        this.InfoListBox.Items.Add(cer.SignatureAlgorithm.FriendlyName);                        
                    }
                }
                
                signedCms.CheckSignature(verifySignatureOnly);
                return true;
            }
            catch (Exception e)
            {
                this.InfoListBox.Items.Add(e.Message);
                return false;
            }
        }

        /// <summary>
        /// Создать подпись
        /// </summary>
        /// <param name="message">
        /// </param>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// Возвращает цифровую подпись
        /// </returns>
        public byte[] Sign(byte[] message, X509Certificate2 certificate)
        {
            try
            {
                var contentInfo = new ContentInfo(message);
                var signedCms = new SignedCms(contentInfo, true); // образом сообщение не будет включено в SignedCms.
                var cmsSigner = new CmsSigner(certificate); // Определяем подписывающего, объектом CmsSigner.
                signedCms.ComputeSignature(cmsSigner, false); // Подписываем CMS/PKCS #7 сообение.
                return signedCms.Encode();
            }
            catch (Exception e)
            {
                this.InfoListBox.Items.Add(e.Message);
                return null;
            }
        }
        public void PrintKeys(RegistryKey rkey)
        {
            var names = rkey.GetSubKeyNames();
            var icount = 0;
            this.InfoListBox.Items.Add("Subkeys of " + rkey.Name);
            this.InfoListBox.Items.Add("-----------------------------------------------");
            foreach (var s in names)
            {
                this.InfoListBox.Items.Add(s);
                icount++;
                if (icount >= 10) break;
            }
        }

        /// <summary>
        /// The save string to file.
        /// </summary>
        /// <param name="fileName">
        /// The file name.
        /// </param>
        /// <param name="src">
        /// The src.
        /// </param>
        private void SaveStringToFile(string fileName, string src)
        {
            try
            {
                using (var streamWriter = new StreamWriter(fileName, false))
                {
                    streamWriter.Write(src);
                    streamWriter.Close();
                }
            }
            catch (Exception exception)
            {
                this.InfoListBox.Items.Add(exception.Message);
            }
        }

        /// <summary>
        /// The get string from file.
        /// </summary>
        /// <param name="fileName">
        /// The file name.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private string GetStringFromFile(string fileName)
        {
            try
            {
                using (var streamReader = new StreamReader(fileName))
                {
                    var src = streamReader.ReadToEnd();
                    streamReader.Close();
                    return src;
                }
            }
            catch (Exception exception)
            {
                this.InfoListBox.Items.Add(exception.Message);
                return string.Empty;
            }
        }

        /// <summary>
        ///     The gpi document sugner form load.
        /// </summary>
        /// <param name="sender">
        ///     The sender.
        /// </param>
        /// <param name="e">
        ///     The e.
        /// </param>
        private void GpiDocumentSugnerFormLoad(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();
            var commandLine = Environment.GetCommandLineArgs();
            if (commandLine.Length > 1)
            {
                this.FileForSignNameTextBox.Text = commandLine[1];
                this.FileForCheckNameTextBox.Text = commandLine[1];
            }

            var cryptographicWrapperModule = new CryptographicWrapperModule();
            var certificateList = cryptographicWrapperModule.GetCertificateList();
            this.CertificatesComboBox.DataSource = certificateList;
            this.CertificateListBox.DataSource = certificateList;
        }

        /// <summary>
        /// The sign atached button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void SignAtachedButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();

            var certificateWrapper = (X509Certificate2Wrapper)this.CertificatesComboBox.SelectedItem;
            var message = File.ReadAllBytes(this.FileForSignNameTextBox.Text);
            var contentInfo = new ContentInfo(message);
            var signedCms = new SignedCms(contentInfo, false);
            var isSingPresent = true;
            try
            {
                signedCms.Decode(message);
            }
            catch
            {
                isSingPresent = false;
            }

            if (isSingPresent)
            {
                this.InfoListBox.Items.Add("Документ содержит подписи:");
                if (signedCms.Certificates.Count > 0)
                {
                    foreach (var cer in signedCms.Certificates)
                    {
                        this.InfoListBox.Items.Add(CryptographicWrapperModule.ExtractCertificateName(cer.SubjectName));
                    }
                }           
            }
            else
            {
                this.InfoListBox.Items.Add("Подписи в документе отсутствуют");                
            }
            
            /*var gpiCryptographicWrapper = new GpiCryptographicWrapper();
            var certificateList = gpiCryptographicWrapper.GetCertificateList();
            foreach (var certificate in certificateList)
            {
                var cmsSigner = new CmsSigner(certificate.Certificat); // Определяем подписывающего, объектом CmsSigner.
                signedCms.ComputeSignature(cmsSigner, false); // Подписываем CMS/PKCS #7 сообение.
            }*/
            
            var cmsSigner = new CmsSigner(certificateWrapper.Certificat); // Определяем подписывающего, объектом CmsSigner.
            signedCms.ComputeSignature(cmsSigner, false); // Подписываем CMS/PKCS #7 сообение.
            
            var signature = signedCms.Encode();
            var outFileName = this.FileForSignNameTextBox.Text;
            if (!this.FileForSignNameTextBox.Text.EndsWith(".sig"))
            {
                outFileName = this.FileForSignNameTextBox.Text + ".sig";
            }

            File.WriteAllBytes(outFileName, signature);
            this.InfoListBox.Items.Add("Документ подписан: " + certificateWrapper.DisplayName);   
        }

        /// <summary>
        /// The assute sign button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void AssuteSignButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();

            var certificateWrapper = (X509Certificate2Wrapper)this.CertificatesComboBox.SelectedItem;
            var message = File.ReadAllBytes(this.FileForSignNameTextBox.Text);
            var contentInfo = new ContentInfo(message);
            var signedCms = new SignedCms(contentInfo, false);
            var isSingPresent = true;
            try
            {
                signedCms.Decode(message);
            }
            catch
            {
                isSingPresent = false;
            }

            if (isSingPresent)
            {
                this.InfoListBox.Items.Add("Документ содержит подписи:");
                if (signedCms.Certificates.Count > 0)
                {
                    foreach (var cer in signedCms.Certificates)
                    {
                        this.InfoListBox.Items.Add(CryptographicWrapperModule.ExtractCertificateName(cer.SubjectName));
                    }
                }
            }
            else
            {
                this.InfoListBox.Items.Add("Подписи в документе отсутствуют");
                return;
            }


            foreach (var sign in signedCms.SignerInfos)
            {
                // if sign.Certificate.SubjectName.Name.Contains("Second"))
                {
                    sign.ComputeCounterSignature(new CmsSigner(certificateWrapper.Certificat));
                }
            }

            var signature = signedCms.Encode();
            var outFileName = this.FileForSignNameTextBox.Text;
            if (!this.FileForSignNameTextBox.Text.EndsWith(".sig"))
            {
                outFileName = this.FileForSignNameTextBox.Text + ".sig";
            }

            File.WriteAllBytes(outFileName, signature);
            this.InfoListBox.Items.Add("Подписи заверены: " + certificateWrapper.DisplayName);
        }

        /// <summary>
        /// The check atached button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void CheckAtachedButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();
            var action = this.VerifySignatureOnlyCheckBox.Checked ? @"Проверка подписи" : @"Проверка подписи и сертификатов";
            this.InfoListBox.Items.Add($"{action} {this.FileForCheckNameTextBox.Text}");

            try
            {
                var signature = File.ReadAllBytes(this.FileForCheckNameTextBox.Text);
                var contentInfo = new ContentInfo(signature);
                var signedCms = new SignedCms(contentInfo, false);
                try
                {
                    signedCms.Decode(signature);
                }
                catch (CryptographicException crex)
                {
                    this.InfoListBox.Items.Add("Не удалось декодировать информационный блок ЭЦП");
                    this.InfoListBox.Items.Add("(возможно документ не подписан)");
                    this.InfoListBox.Items.Add("Ошибка: " + crex.Message);
                }

                /*ClientCredentials creds = new ClientCredentials();
                creds.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.PeerTrust; // Configure peer trust.
                creds.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.ChainTrust; // Configure chain trust.
                creds.*/
                var count = 1;
                if (signedCms.SignerInfos.Count > 0)
                {
                    this.InfoListBox.Items.Add("Документ содержит подписи:");
                    foreach (var signerInfos in signedCms.SignerInfos)
                    {
                        this.InfoListBox.Items.Add(string.Format("{0} {1}", count++, CryptographicWrapperModule.ExtractCertificateName(signerInfos.Certificate.SubjectName)));
                        if (signerInfos.CounterSignerInfos.Count > 0)
                        {
                            foreach (var counterSignerInfos in signerInfos.CounterSignerInfos)
                            {
                                this.InfoListBox.Items.Add(string.Format("       (подпись заверена {0})", CryptographicWrapperModule.ExtractCertificateName(counterSignerInfos.Certificate.SubjectName)));        
                            }
                        }

                        try
                        {
                            signerInfos.CheckSignature(this.VerifySignatureOnlyCheckBox.Checked);
                            this.InfoListBox.Items.Add("Проверка: Ok!");
                            signerInfos.Certificate.Verify();
                            
                            foreach (X509VerificationFlags enumValue in Enum.GetValues(typeof(X509VerificationFlags)))
                            {
                                var chain = new X509Chain
                                                      {
                                                          ChainPolicy =
                                                             { 
                                                                  RevocationMode = X509RevocationMode.Offline,
                                                                  VerificationFlags = enumValue
                                                              }
                                                      };
                                chain.Build(signerInfos.Certificate);

                                foreach (var element in chain.ChainElements)
                                {
                                    this.InfoListBox.Items.Add($"Element issuer name: {element.Certificate.Issuer}");
                                    this.InfoListBox.Items.Add($"Element certificate valid until: {element.Certificate.NotAfter}");
                                    this.InfoListBox.Items.Add($"Element certificate is valid: {element.Certificate.Verify()}");
                                    this.InfoListBox.Items.Add($"Element error status length: {element.ChainElementStatus.Length}");
                                    this.InfoListBox.Items.Add($"Element information: {element.Information}");
                                    this.InfoListBox.Items.Add($"Number of element extensions: {element.Certificate.Extensions.Count}{Environment.NewLine}");

                                    if (chain.ChainStatus.Length > 0)
                                    {
                                        for (int index = 0; index < element.ChainElementStatus.Length; index++)
                                        {
                                            this.InfoListBox.Items.Add(element.ChainElementStatus[index].Status);
                                            this.InfoListBox.Items.Add(element.ChainElementStatus[index].StatusInformation);
                                        }
                                    }
                                }
                            }
                        }
                        catch (CryptographicException crex)
                        {
                            this.InfoListBox.Items.Add(string.Format("Проверка: {0}", crex.Message));                            
                        }
                    }
                }
                else
                {
                    this.InfoListBox.Items.Add("Подписи отсутствуют");
                }

                this.InfoListBox.Items.Add("Ok!");
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
            }
        }

        /// <summary>
        /// The extract document button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ExtractDocumentButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();
            this.InfoListBox.Items.Add("Извлечение документа из: " + this.FileForCheckNameTextBox.Text);         
            try
            {
                /*var signature = File.ReadAllBytes(this.FileForCheckNameTextBox.Text);
                var contentInfo = new ContentInfo(signature);
                var signedCms = new SignedCms(contentInfo, false);
                signedCms.Decode(signature);
                var content = signedCms.ContentInfo.Content;*/

                var content = this.ExtractContent(this.FileForCheckNameTextBox.Text);
                
                var tmpFileName = Path.GetTempFileName(); 
                var fileName = Path.GetFileNameWithoutExtension(this.FileForCheckNameTextBox.Text);
                if (!string.IsNullOrEmpty(fileName))
                {
                    tmpFileName = Path.Combine(Path.GetTempPath(), fileName);
                }

                File.WriteAllBytes(tmpFileName, content);
                Process.Start(tmpFileName);

                this.InfoListBox.Items.Add("Ok!");
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
            }
        }

        private byte[] ExtractContent(string fileName)
        {
            var signature = File.ReadAllBytes(fileName);                
            var contentInfo = new ContentInfo(signature);
            var signedCms = new SignedCms(contentInfo, false);
            signedCms.Decode(signature);
            return signedCms.ContentInfo.Content;            
        }

        /// <summary>
        /// The import certificate button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ImportCertificateButtonClick(object sender, EventArgs e)
        {
            try
            {
                var openFileDialog = new OpenFileDialog
                {
                    Filter = @"cer files (*.cer)|*.cer|All files (*.*)|*.*",
                    FilterIndex = 1,
                    RestoreDirectory = true
                };

                if (openFileDialog.ShowDialog() != DialogResult.OK)
                {
                    return;
                }

                var certificate = new X509Certificate2();
                certificate.Import(openFileDialog.FileName);
                var cryptographicWrapperModule = new CryptographicWrapperModule();
                var result = cryptographicWrapperModule.InstallCertificateToUserStore(certificate);
                if (result)
                {
                    this.InfoListBox.Items.Add("Certificate installed!");
                    var certificateList = cryptographicWrapperModule.GetCertificateList();
                    this.CertificatesComboBox.DataSource = certificateList;
                    this.CertificateListBox.DataSource = certificateList;
                }
                else
                {
                    this.InfoListBox.Items.Add("Error!");
                    cryptographicWrapperModule.LastError.ForEach(c => this.InfoListBox.Items.Add(c));
                }
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
            }
        }

        /// <summary>
        /// The remove certificate button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void RemoveCertificateButtonClick(object sender, EventArgs e)
        {
            var certificateWrapper = (X509Certificate2Wrapper)this.CertificateListBox.SelectedItem;
            var cryptographicWrapperModule = new CryptographicWrapperModule();
            var result = cryptographicWrapperModule.RemoveCertificateFromUserStore(certificateWrapper.Certificat);
            if (result)
            {
                this.InfoListBox.Items.Add("Certificate installed!");
                var certificateList = cryptographicWrapperModule.GetCertificateList();
                this.CertificatesComboBox.DataSource = certificateList;
                this.CertificateListBox.DataSource = certificateList;
            }
            else
            {
                this.InfoListBox.Items.Add("Error!");
                cryptographicWrapperModule.LastError.ForEach(c => this.InfoListBox.Items.Add(c));
            }
        }

        /// <summary>
        /// The create mini dump button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void CreateMiniDumpButtonClick(object sender, EventArgs e)
        {
            const int A = 3;
            // ReSharper disable once ConvertToConstant.Local
            var b = 0;
            // ReSharper disable once UnusedVariable
            var c = A /b;
        }

        /// <summary>
        /// The generate key pair button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void GenerateKeyPairButtonClick(object sender, EventArgs e)
        {
            using (var rsaProvider = new RSACryptoServiceProvider(1024))
            {
                var justPublicKey = rsaProvider.ToXmlString(false);
                this.SaveStringToFile(@"D:\TEST\GpiPublicKey.bin", justPublicKey);
                
                var publicAndPrivateKeys = rsaProvider.ToXmlString(true);
                this.SaveStringToFile(@"D:\TEST\GpiKeyPair.bin", publicAndPrivateKeys);
            }
        }

        /// <summary>
        /// The encrypt button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void EncryptButtonClick(object sender, EventArgs e)
        {
            var byteConverter = new ASCIIEncoding();
            byte[] dataToEncrypt = byteConverter.GetBytes("Data to Encrypt");

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                var justPublicKey = this.GetStringFromFile(@"D:\TEST\GpiPublicKey.bin");
                rsa.FromXmlString(justPublicKey);
                var encryptedData = rsa.Encrypt(dataToEncrypt, false);
                File.WriteAllBytes(@"D:\TEST\request0.txt.sig", encryptedData);
            }
        }

        /// <summary>
        /// The decrypt button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void DecryptButtonClick(object sender, EventArgs e)
        {
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                var publicAndPrivateKeys = this.GetStringFromFile(@"D:\TEST\GpiKeyPair.bin");
                rsa.FromXmlString(publicAndPrivateKeys);
                var encryptedData = File.ReadAllBytes(@"D:\TEST\xxx.bin");
                var decryptedData = rsa.Decrypt(encryptedData, false);
                var byteConverter = new ASCIIEncoding();
                this.InfoListBox.Items.Add($"Decrypted plaintext: {byteConverter.GetString(decryptedData)}");
            }
        }

        /// <summary>
        /// The hash button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void HashButtonClick(object sender, EventArgs e)
        {
            byte[] dataToEncrypt = File.ReadAllBytes(@"D:\TEST\test.txt");
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                var publicAndPrivateKeys = this.GetStringFromFile(@"D:\TEST\GpiKeyPair.bin");
                rsa.FromXmlString(publicAndPrivateKeys);   

                var signedBytes = rsa.SignData(dataToEncrypt, CryptoConfig.MapNameToOID("SHA512"));
                File.WriteAllBytes(@"D:\TEST\request0.txt.sig", signedBytes);

                var result = rsa.VerifyData(dataToEncrypt, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
                this.InfoListBox.Items.Add(BitConverter.ToString(dataToEncrypt).Replace("-", string.Empty));
                this.InfoListBox.Items.Add(BitConverter.ToString(signedBytes).Replace("-", string.Empty));
                this.InfoListBox.Items.Add(result);
            }

            var hash = new SHA512Managed();
            var hashedData = hash.ComputeHash(dataToEncrypt);
            File.WriteAllBytes(@"D:\TEST\request0.txt.sig", hashedData);
        }

        private void ExtractButtonClick(object sender, EventArgs e)
        {
            try
            {
                var dataToEncrypt = File.ReadAllBytes(@"D:\TEST\test.txt");
                
                byte[] encryptedData;
                using (var rsa1 = new RSACryptoServiceProvider(1024))
                {
                    var justPublicKey1 = this.GetStringFromFile(@"D:\TEST\GpiPublicKey.bin");
                    rsa1.FromXmlString(justPublicKey1);
                    encryptedData = rsa1.Encrypt(dataToEncrypt, false);
                }

                using (var rsa2 = new RSACryptoServiceProvider(1024))
                {
                    var publicAndPrivateKeys2 = this.GetStringFromFile(@"D:\TEST\GpiKeyPair.bin");
                    rsa2.FromXmlString(publicAndPrivateKeys2);
                    var decryptedData = rsa2.Decrypt(encryptedData, false);
                    
                    var byteConverter = new ASCIIEncoding();
                    this.InfoListBox.Items.Add($"Decrypted plaintext: {byteConverter.GetString(decryptedData)}");

                    var signedBytes = File.ReadAllBytes(@"D:\TEST\Test.sig");
                    var result = rsa2.VerifyData(decryptedData, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
                    this.InfoListBox.Items.Add(rsa2.CspKeyContainerInfo.UniqueKeyContainerName);
                    this.InfoListBox.Items.Add(BitConverter.ToString(decryptedData).Replace("-", string.Empty));
                    this.InfoListBox.Items.Add(BitConverter.ToString(signedBytes).Replace("-", string.Empty));
                    this.InfoListBox.Items.Add(result);
                }
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
            }
        }

        /// <summary>
        /// The bouncy castle button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void BouncyCastleButtonClick(object sender, EventArgs e)
        {
            // Install-Package BouncyCastle -Version 1.8.1
            var keyGenerate = new RsaKeyPairGenerator();
            keyGenerate.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024));

            AsymmetricCipherKeyPair kp1 = keyGenerate.GenerateKeyPair();
            var gen1 = new X509V3CertificateGenerator();
            var certName1 = new X509Name("CN=DupelMan1");
            var serialNo1 = new BigInteger("1", 10);

            gen1.SetSerialNumber(serialNo1);
            gen1.SetSubjectDN(certName1);
            gen1.SetIssuerDN(certName1);
            gen1.SetNotAfter(DateTime.Now.AddYears(1));
            gen1.SetNotBefore(DateTime.Now.AddDays(-1));
            gen1.SetSignatureAlgorithm("SHA1WITHRSA");
            gen1.SetPublicKey(kp1.Public);
            var myCert1 = gen1.Generate(kp1.Private);
            var certBytes1 = DotNetUtilities.ToX509Certificate(myCert1).Export(X509ContentType.Cert);
            File.WriteAllBytes("D:\\DupelMan1.cer", certBytes1);

            AsymmetricCipherKeyPair kp2 = keyGenerate.GenerateKeyPair();
            var gen2 = new X509V3CertificateGenerator();
            var certName2 = new X509Name("CN=DupelMan2");
            var serialNo2 = new BigInteger("2", 10);

            gen2.SetSerialNumber(serialNo2);
            gen2.SetSubjectDN(certName2);
            gen2.SetIssuerDN(certName2);
            gen2.SetNotAfter(DateTime.Now.AddYears(1));
            gen2.SetNotBefore(DateTime.Now.AddDays(-1));
            gen2.SetSignatureAlgorithm("SHA1WITHRSA");
            gen2.SetPublicKey(kp2.Public);
            gen2.AddExtension(
                            X509Extensions.AuthorityKeyIdentifier.Id,
                            false,
                            new AuthorityKeyIdentifier(
                                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp1.Public),
                                new GeneralNames(new GeneralName(certName1)),
                                serialNo1));

            var myCert = gen2.Generate(kp1.Private);
            var certBytes = DotNetUtilities.ToX509Certificate(myCert).Export(X509ContentType.Cert);
            File.WriteAllBytes("D:\\DupelMan2.cer", certBytes);
            

            //this.SaveByteToFile(@"D:\private.bin", kp.Private);
            //this.SaveByteToFile(@"D:\public.bin", kp.Public);

            /*var certBytes = DotNetUtilities.ToX509Certificate(myCert).Export(X509ContentType.Cert, "12345678");
            var fs = new FileStream("D:\\DupelMan.crt", FileMode.CreateNew);
            fs.Write(certBytes, 0, certBytes.Length);
            fs.Flush();
            fs.Close();*/

            certBytes = DotNetUtilities.ToX509Certificate(myCert).Export(X509ContentType.Cert, "12345678");
            File.WriteAllBytes("D:\\DupelMan.pfx", certBytes);

            /*var fs1 = new FileStream("D:\\DupelMan.pfx", FileMode.CreateNew);
            fs1.Write(certBytes, 0, certBytes.Length);
            fs1.Flush();
            fs1.Close();*/


            /*var cert2 = new X509Certificate2(certBytes, "12345678"); // Convert X509Certificate to X509Certificate2
            var rsaPriv = DotNetUtilities.ToRSA(kp.Private as RsaPrivateCrtKeyParameters); // Convert BouncyCastle Private Key to RSA
            var csp = new CspParameters { KeyContainerName = "MyKeyContainer" }; // Setup RSACryptoServiceProvider with "KeyContainerName" set

            var rsaPrivate = new RSACryptoServiceProvider(csp);
            rsaPrivate.ImportParameters(rsaPriv.ExportParameters(true)); // Import private key from BouncyCastle's rsa
            cert2.PrivateKey = rsaPrivate; // Set private key on our X509Certificate2
       
            var cert2Bytes = cert2.Export(X509ContentType.Pkcs12, "12345678");

            var data = File.ReadAllBytes(@"D:\GPEngRootCA.cer");*/
            //SHA1 sha = new SHA1CryptoServiceProvider();
            //var signedBytes = sha.ComputeHash(data);
            //SHA1 shaM = new SHA1Managed();
            //var signedBytes = shaM.ComputeHash(data);
            //this.InfoListBox.Items.Add(BitConverter.ToString(signedBytes).Replace("-", " "));

            /*if (File.Exists(@"D:\DupelMan.pfx"))
            {
                File.Delete(@"D:\DupelMan.pfx");
            }
           
            File.WriteAllBytes(@"D:\DupelMan.pfx", cert2.Export(X509ContentType.Pkcs12, "12345678"));*/


            this.InfoListBox.Items.Add(@"Ok!");
        }

        public static X509Certificate2 OpenCertificate(string pfxPath, string contrasenia)
        {
            var ms = new MemoryStream(File.ReadAllBytes(pfxPath));

            var st = new Org.BouncyCastle.Pkcs.Pkcs12Store(ms, contrasenia.ToCharArray());

            var alias = st.Aliases.Cast<string>().FirstOrDefault(p => st.IsCertificateEntry(p));
            var keyEntryX = st.GetCertificate(alias);

            var x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(keyEntryX.Certificate));

            alias = st.Aliases.Cast<string>().FirstOrDefault(p => st.IsKeyEntry(p));
            var keyEntry = st.GetKey(alias);
            var intermediateProvider = (RSACryptoServiceProvider)DotNetUtilities.ToRSA((Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyEntry.Key);

            x509.PrivateKey = intermediateProvider;

            return x509;
        }

        /// <summary>
        /// The add context menu button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void AddContextMenuButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();
            this.InfoListBox.Items.Add("Добавление в контектное меню");            
            RegistryKey signRegmenu = null;
            RegistryKey commandRegmenu = null;
            try
            {
                signRegmenu = Registry.ClassesRoot.CreateSubKey("*\\Shell\\GpiDocumentSigner");
                if (signRegmenu != null)
                {
                    signRegmenu.SetValue(string.Empty, @"ЭЦП");
                    commandRegmenu = Registry.ClassesRoot.CreateSubKey("*\\Shell\\GpiDocumentSigner\\command");
                    if (commandRegmenu != null)
                    {
                        commandRegmenu.SetValue(string.Empty, @"D:\URB31075\GPIDocumentSigner\GPIDocumentSigner\bin\Debug\GPIDocumentSigner.exe %1");
                        MessageBox.Show(@"Приложение успешно добавлено в контекстное меню!", @"Внимание!", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }

                this.InfoListBox.Items.Add("Ok!"); // PrintKeys(Registry.ClassesRoot.OpenSubKey(".Hren\\Shell\\Sign"));
            }
            catch (Exception ex)
            {
                MessageBox.Show(@"Ошибка при добавлении приложения в контекстное меню: " + ex.Message, @"Ошибка!", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                if (signRegmenu != null)
                {
                    signRegmenu.Close();
                }

                if (commandRegmenu != null)
                {
                    commandRegmenu.Close();
                }
            } 
        }

        /// <summary>
        /// The remove context menu button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void RemoveContextMenuButtonClick(object sender, EventArgs e)
        {
            this.InfoListBox.Items.Clear();
            this.InfoListBox.Items.Add("Удаление из контектного меню");              
            try
            {
                Registry.ClassesRoot.DeleteSubKey("*\\Shell\\GpiDocumentSigner\\command");
                Registry.ClassesRoot.DeleteSubKey("*\\Shell\\GpiDocumentSigner");
                this.InfoListBox.Items.Add("Ok!"); 
            }
            catch (Exception ex)
            {
                MessageBox.Show(@"Ошибка при удалении приложения из контекстное меню: " + ex.Message, @"Ошибка!", MessageBoxButtons.OK, MessageBoxIcon.Error);                
            }
        }

        private void ListDirButtonClick(object sender, EventArgs e)
        {
            try
            {
                var result = Directory.Exists(@"\\EXCHANGE10\Address");
                this.InfoListBox.Items.Add(result);
                
                var dirList = Directory.GetDirectories(@"\\EXCHANGE10\Address");
                foreach (var dir in dirList)
                {
                    this.InfoListBox.Items.Add(dir);
                }

                result = Directory.Exists(@"\\EXCHANGE10\MessageTracking$");
                this.InfoListBox.Items.Add(result);
                var fileList = Directory.GetDirectories(@"\\EXCHANGE10\MessageTracking$");
                foreach (var file in fileList)
                {
                    this.InfoListBox.Items.Add(file);
                }

                fileList = Directory.GetFiles(@"\\EXCHANGE10\MessageTracking$");
                foreach (var file in fileList)
                {
                    this.InfoListBox.Items.Add(file);
                }

                //var fileList = Directory.GetFiles(@"\\Exсhange10\MessageTracking\");
            }
            catch (Exception ex)
            {
                this.InfoListBox.Items.Add(ex.Message);
            }
        }

        /// <summary>
        /// The create request button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void CreateRequestButtonClick(object sender, EventArgs e)
        {
            var gpiCryptographicWrapper = new CryptographicWrapperModule();
            var request = gpiCryptographicWrapper.CreateActiveDirectoryCertificateRequest("User");
            var response = gpiCryptographicWrapper.SendActiveDirectoryCertificateRequest(request);
            var result = gpiCryptographicWrapper.InstallCertificateResponse(response);
            this.InfoListBox.Items.Add(result ? "Certificate installed!" : "Error");
            if (result)
            {
                this.InfoListBox.Items.Add("Certificate installed!");
                var certificateList = gpiCryptographicWrapper.GetCertificateList();
                this.CertificatesComboBox.DataSource = certificateList;
                this.CertificateListBox.DataSource = certificateList;
            }
            else
            {
                this.InfoListBox.Items.Add("Error!");
                gpiCryptographicWrapper.LastError.ForEach(c => this.InfoListBox.Items.Add(c));
            }
        }

        /// <summary>
        /// The file name button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void FileForSignNameButtonClick(object sender, EventArgs e)
        {
            var openFileDialog = new OpenFileDialog
                 {
                     Filter = @"sig files (*.sig)|*.sig|All files (*.*)|*.*",
                     FilterIndex = 2,
                     RestoreDirectory = true
                 };

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.FileForSignNameTextBox.Text = openFileDialog.FileName;
            }
        }

        /// <summary>
        /// The file for check name click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void FileForCheckNameClick(object sender, EventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = @"sig files (*.sig)|*.sig|All files (*.*)|*.*",
                FilterIndex = 1,
                RestoreDirectory = true
            };

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.FileForCheckNameTextBox.Text = openFileDialog.FileName;
                this.CheckAtachedButtonClick(null, null);
            }
        }
    }
}

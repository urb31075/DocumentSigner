// --------------------------------------------------------------------------------------------------------------------
// <copyright file="GpiCryptographicWrapper.cs" company="urb31075">
// All Right Reserved  
// </copyright>
// <summary>
//   Defines the GpiCryptographicWrapper type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace GpiCryptographic
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    using CERTCLILib;

    using CERTENROLLLib;

    /// <summary>
    /// The gpi cryptographic wrapper.
    /// </summary>
    public class CryptographicWrapperModule
    {
        /// <summary>
        /// The cc uipickconfig.
        /// </summary>
        private const int CcUipickconfig = 0x1;

        /// <summary>
        /// The cr in base 64.
        /// </summary>
        private const int CrInBase64 = 0x1;

        /// <summary>
        /// The cr in formatany.
        /// </summary>
        private const int CrInFormatany = 0;

        /// <summary>
        /// The cr disp issued.
        /// </summary>
        private const int CrDispIssued = 0x3;

        /// <summary>
        /// The cr disp under submission.
        /// </summary>
        private const int CrDispUnderSubmission = 0x5;

        /// <summary>
        /// The cr out base 64.
        /// </summary>
        private const int CrOutBase64 = 0x1;

        /// <summary>
        /// The cr out chain.
        /// </summary>
        private const int CrOutChain = 0x100;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicWrapper"/> class.
        /// </summary>
        public CryptographicWrapperModule()
        {
            this.LastError = new List<string>();
        }

        /// <summary>
        /// Gets the last error.
        /// </summary>
        public List<string> LastError { get; private set; }

        /// <summary>
        /// The extract certificate name.
        /// </summary>
        /// <param name="subjectName">
        /// The subject name.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string ExtractCertificateName(X500DistinguishedName subjectName)
        {
            var name = string.Empty;
            try
            {
                var str = subjectName.Decode(X500DistinguishedNameFlags.UseUTF8Encoding);
                if (!string.IsNullOrEmpty(str))
                {
                    name = str.Split(',').Select(keyValuePair => keyValuePair.Split('=')).First(param => param[0].Trim() == "CN")[1];
                }

                return name;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// The extract certificate name.
        /// </summary>
        /// <param name="subjectName">
        /// The subject name.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string ExtractCertificateName(string subjectName)
        {
            var name = string.Empty;
            try
            {
                if (!string.IsNullOrEmpty(subjectName))
                {
                    name = subjectName.Split(',').Select(keyValuePair => keyValuePair.Split('=')).First(param => param[0].Trim() == "CN")[1];
                }

                return name;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// The get certificate list.
        /// </summary>
        /// <returns>
        /// Возврат списка сертификатов из личного хранилища пользователя.
        /// </returns>
        public List<X509Certificate2Wrapper> GetCertificateList()
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            var certificateList = new List<X509Certificate2Wrapper>();

            foreach (var certificat in store.Certificates)
            {
                var cer = new X509Certificate2Wrapper
                     {
                         Certificat = certificat,
                         DisplayName = ExtractCertificateName(certificat.SubjectName)
                     };

                if (cer.Certificat.HasPrivateKey)
                {
                    certificateList.Add(cer);
                }
            }

            return certificateList;
        }

        /// <summary>
        /// The create active directory certificate request.
        /// </summary>
        /// <param name="templateName">
        /// The template name.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string CreateActiveDirectoryCertificateRequest(string templateName)
        {
            //// https://blogs.msdn.microsoft.com/alejacma/2008/09/05/how-to-create-a-certificate-request-with-certenroll-and-net-c/
            //// http://geekswithblogs.net/shaunxu/archive/2012/01/13/working-with-active-directory-certificate-service-via-c.aspx
            
            this.LastError.Clear();            
            try
            {
                var cspInformations = new CCspInformations();
                cspInformations.AddAvailableCsps();

                var privateKey = new CX509PrivateKey // Создали приватный ключ
                {
                    Length = 2048,
                    KeySpec = X509KeySpec.XCN_AT_SIGNATURE,
                    KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES,
                    MachineContext = false,
                    ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG,
                    CspInformations = cspInformations
                };

                privateKey.Create();

                var objPkcs10 = new CX509CertificateRequestPkcs10();
                objPkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, privateKey, templateName);
                var objEnroll = new CX509Enrollment();
                objEnroll.InitializeFromRequest(objPkcs10);
                var strRequest = objEnroll.CreateRequest(); // Значение по уолчанию: EncodingType.XCN_CRYPT_STRING_BASE64
                return strRequest;
            }
            catch (Exception ex)
            {
                this.LastError.Add(ex.Message);                
                return string.Empty;
            }
        }

        /// <summary>
        /// The send active directory certificate request.
        /// </summary>
        /// <param name="request">
        /// The request.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string SendActiveDirectoryCertificateRequest(string request)
        {
            this.LastError.Clear();
            try
            {
                CCertConfig objCertConfig = new CCertConfigClass(); // Create all the objects that will be required
                CCertRequest objCertRequest = new CCertRequestClass();
                var strCaConfig = objCertConfig.GetConfig(CcUipickconfig); // strCAConfig = objCertConfig.GetConfig(CC_DEFAULTCONFIG); // Get CA config from UI
                var result = objCertRequest.Submit(CrInBase64 | CrInFormatany, request, null, strCaConfig); // Submit the request
                // Check the submission status
                if (result != CrDispIssued)
                {
                    // Not enrolled
                    var dispositionMessage = objCertRequest.GetDispositionMessage();
                    if (result == CrDispUnderSubmission)
                    {
                        // Pending
                        this.LastError.Add("The submission is pending: " + dispositionMessage);
                        return string.Empty;
                    }
                    else
                    {
                        // Failed
                        this.LastError.Add("The submission failed: " + dispositionMessage);
                        this.LastError.Add("Last status: " + objCertRequest.GetLastStatus());
                        return string.Empty;
                    }
                }

                var certificate = objCertRequest.GetCertificate(CrOutBase64 | CrOutChain); // Get the certificate
                return certificate;
            }
            catch (Exception ex)
            {
                this.LastError.Add(ex.Message);
                return string.Empty;
            }
        }

        /// <summary>
        /// The install certificate response.
        /// </summary>
        /// <param name="response">
        /// The response.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public bool InstallCertificateResponse(string response)
        {
            this.LastError.Clear();            
            try
            {
                var objEnroll = new CX509EnrollmentClass();
                objEnroll.Initialize(X509CertificateEnrollmentContext.ContextUser);
                objEnroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedRoot, response, EncodingType.XCN_CRYPT_STRING_BASE64, null);
                return true;
            }
            catch (Exception ex)
            {
                this.LastError.Add(ex.Message);
                return false;
            } 
        }

        /// <summary>
        /// The install certificate to user store.
        /// </summary>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public bool InstallCertificateToUserStore(X509Certificate2 certificate)
        {
            this.LastError.Clear();
            try
            {
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);
                store.Close();
                return true;
            }
            catch (Exception ex)
            {
                this.LastError.Add(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// The remove certificate from user store.
        /// </summary>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public bool RemoveCertificateFromUserStore(X509Certificate2 certificate)
        {
            this.LastError.Clear();
            try
            {
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Remove(certificate);
                store.Close();
                return true;
            }
            catch (Exception ex)
            {
                this.LastError.Add(ex.Message);
                return false;
            }
        }
    }

    /// <summary>
    /// The x 509 certificate 2 wrapper.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1402:FileMayOnlyContainASingleClass", Justification = "Reviewed. Suppression is OK here.")]
    public class X509Certificate2Wrapper
    {
        /// <summary>
        /// Gets or sets the certificat.
        /// </summary>
        public X509Certificate2 Certificat { get; set; }

        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// The to string.
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public override string ToString()
        {
            return this.DisplayName;
        }
    }
}
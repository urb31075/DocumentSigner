// --------------------------------------------------------------------------------------------------------------------
// <copyright file="KeysForPGPEncryptionDecryption.cs" company="urb31075">
//  All Roght Reserved 
// </copyright>
// <summary>
//   Defines the KeysForPGPEncryptionDecryption type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace PGPSnippet.KeyGeneration
{
    using System;
    using System.IO;

    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;

    /// <summary>
    /// The keys for pgp encryption decryption.
    /// </summary>
    public class KeysForPgpEncryptionDecryption
    {
        /// <summary>
        /// The generate key.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="keyStoreUrl">
        /// The key store url.
        /// </param>
        public static void GenerateKey(string username, string password, string keyStoreUrl)
        {
            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            FileStream out1 = new FileInfo(string.Format("{0}PGPPrivateKey.asc", keyStoreUrl)).OpenWrite();
            FileStream out2 = new FileInfo(string.Format("{0}PGPPublicKey.asc", keyStoreUrl)).OpenWrite();
            ExportKeyPair(out1, out2, kp.Public, kp.Private, username, password.ToCharArray(), true);
            out1.Close();
            out2.Close();
        }

        /// <summary>
        /// The export key pair.
        /// </summary>
        /// <param name="secretOut">
        /// The secret out.
        /// </param>
        /// <param name="publicOut">
        /// The public out.
        /// </param>
        /// <param name="publicKey">
        /// The public key.
        /// </param>
        /// <param name="privateKey">
        /// The private key.
        /// </param>
        /// <param name="identity">
        /// The identity.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <param name="armor">
        /// The armor.
        /// </param>
        private static void ExportKeyPair(Stream secretOut, Stream publicOut, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, string identity, char[] passPhrase, bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            var secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification, 
                PublicKeyAlgorithmTag.RsaGeneral, 
                publicKey, 
                privateKey, 
                DateTime.Now, 
                identity, 
                SymmetricKeyAlgorithmTag.Cast5, 
                passPhrase, 
                null, 
                null, 
                new SecureRandom());

            secretKey.Encode(secretOut);

            secretOut.Close();

            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Close();
        }
    }
}
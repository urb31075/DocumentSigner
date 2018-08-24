namespace PGPSnippet.Keys
{
    using System;
    using System.IO;
    using System.Linq;

    using Org.BouncyCastle.Bcpg.OpenPgp;

    /// <summary>
    /// The pgp encryption keys.
    /// </summary>
    public class PgpEncryptionKeys
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PgpEncryptionKeys"/> class.
        /// </summary>
        /// <param name="publicKeyPath">
        /// The public key path.
        /// </param>
        /// <param name="privateKeyPath">
        /// The private key path.
        /// </param>
        /// <param name="passPhrase">
        /// The pass phrase.
        /// </param>
        /// <exception cref="ArgumentException">
        /// </exception>
        public PgpEncryptionKeys(string publicKeyPath, string privateKeyPath, string passPhrase)
        {
            if (!File.Exists(publicKeyPath))
            {
                throw new ArgumentException("Public key file not found", "publicKeyPath");
            }

            if (!File.Exists(privateKeyPath))
            {
                throw new ArgumentException("Private key file not found", "privateKeyPath");
            }

            if (string.IsNullOrEmpty(passPhrase))
            {
                throw new ArgumentException("passPhrase is null or empty.", "passPhrase");
            }

            this.PublicKey = this.ReadPublicKey(publicKeyPath);
            this.SecretKey = this.ReadSecretKey(privateKeyPath);
            this.PrivateKey = this.ExtractPrivateKey(passPhrase);
        }

        /// <summary>
        /// Gets the private key.
        /// </summary>
        public PgpPrivateKey PrivateKey { get; private set; }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public PgpPublicKey PublicKey { get; private set; }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        public PgpSecretKey SecretKey { get; private set; }

        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key =
                    kRing.GetPublicKeys().Cast<PgpPublicKey>().Where(k => k.IsEncryptionKey).FirstOrDefault();

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }

        private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                PgpSecretKey key =
                    kRing.GetSecretKeys().Cast<PgpSecretKey>().Where(k => k.IsSigningKey).FirstOrDefault();

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }

        private PgpPrivateKey ExtractPrivateKey(string passPhrase)
        {
            PgpPrivateKey privateKey = this.SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)
            {
                return privateKey;
            }

            throw new ArgumentException("No private key found in secret key.");
        }

        private PgpPublicKey ReadPublicKey(string publicKeyPath)
        {
            using (Stream keyIn = File.OpenRead(publicKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);

                PgpPublicKey foundKey = this.GetFirstPublicKey(publicKeyRingBundle);

                if (foundKey != null)
                {
                    return foundKey;
                }
            }

            throw new ArgumentException("No encryption key found in public key ring.");
        }

        private PgpSecretKey ReadSecretKey(string privateKeyPath)
        {
            using (Stream keyIn = File.OpenRead(privateKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);

                PgpSecretKey foundKey = this.GetFirstSecretKey(secretKeyRingBundle);

                if (foundKey != null)
                {
                    return foundKey;
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }
    }
}
using System.Text;
using NSec.Cryptography;

namespace Manifold.Signature
{
    public class Signature
    {
        private byte[] signature;
        private byte[] publicKey;
        private byte[] endorsement;

        /// <summary>
        /// extracts the three parts of the manifold signature header and parses
        /// them to a valid Base64.Might throw an InvalidSignatureException if
        /// the signature is not made of three parts.
        /// </summary>
        /// <param name="signature">The signature header.</param>
        public Signature(string signature)
        {
            string[] signatureParts = signature.Split(' ');
            if (signatureParts.Length != 3)
            {
                throw new InvalidSignatureException("Could not parse signature chain");
            }

            this.signature = Helpers.DecodeBase64URL(signatureParts[0]);
            this.publicKey = Helpers.DecodeBase64URL(signatureParts[1]);
            this.endorsement = Helpers.DecodeBase64URL(signatureParts[2]);
        }

        /// <summary>
        /// Validates the given public key and body against the signature to
        /// make sure it was properly signed by manifold.See the docs for more
        /// info on how requests are signed.
        /// </summary>
        /// <returns>Return true if no error occured.</returns>
        /// <param name="masterKey">The main master public key to verify against.</param>
        /// <param name="body">The final canonized body from Verifier.</param>
        public bool Validate(string masterKey, string body)
        {
            SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;
            byte[] masterBytes = Helpers.DecodeBase64URL(masterKey);

            PublicKey masterPublicKey = PublicKey.Import(algorithm, masterBytes, KeyBlobFormat.RawPublicKey);
            if (!algorithm.Verify(masterPublicKey, this.publicKey, this.endorsement))
            {
                throw new InvalidSignatureException("Request Public Key was not endorsed by Manifold");
            }

            PublicKey livePublicKey = PublicKey.Import(algorithm, this.publicKey, KeyBlobFormat.RawPublicKey);
            if (!algorithm.Verify(livePublicKey, Encoding.UTF8.GetBytes(body), this.signature))
            {
                throw new InvalidSignatureException("Request was not signed by included Public Key");
            }
            return true;
        }
    }
}

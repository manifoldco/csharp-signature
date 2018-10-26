using System;
namespace Manifold.Signature
{
    public static class Helpers
    {
        public static byte[] DecodeBase64URL(string encodedString)
        {
            encodedString = encodedString.Replace('_', '/').Replace('-', '+');
            switch (encodedString.Length % 4)
            {
                case 2: encodedString += "=="; break;
                case 3: encodedString += "="; break;
            }
            return System.Convert.FromBase64String(encodedString);
        }
    }
}

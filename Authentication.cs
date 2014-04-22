using System;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    public static class Authentication
    {
        private static readonly ASCIIEncoding m_encoding;
        private static readonly byte[] m_keyBytes;

        static Authentication()
        {
            m_encoding = new ASCIIEncoding();
            m_keyBytes = m_encoding.GetBytes(Constants.PrivateKey);
        }

        public static string Encode(string publicKey, int choice = 2)
        {
            byte[] hashMessage = null;
            byte[] messageBytes = m_encoding.GetBytes(publicKey);

            switch (choice%6)
            {
                case 0:
                    var hmacmd5 = new HMACMD5(m_keyBytes);
                    hashMessage = hmacmd5.ComputeHash(messageBytes);
                    break;
                case 1:
                    var hmacripedmd160 = new HMACRIPEMD160(m_keyBytes);
                    hashMessage = hmacripedmd160.ComputeHash(messageBytes);
                    break;
                case 2:
                    var hmacsha1 = new HMACSHA1(m_keyBytes);
                    hashMessage = hmacsha1.ComputeHash(messageBytes);
                    break;
                case 3:
                    var hmacsha256 = new HMACSHA256(m_keyBytes);
                    hashMessage = hmacsha256.ComputeHash(messageBytes);
                    break;
                case 4:
                    var hmacsha384 = new HMACSHA384(m_keyBytes);
                    hashMessage = hmacsha384.ComputeHash(messageBytes);
                    break;
                case 5:
                    var hmacsha512 = new HMACSHA512(m_keyBytes);
                    hashMessage = hmacsha512.ComputeHash(messageBytes);
                    break;
            }

            return Convert.ToBase64String(hashMessage);
        }
    }
}
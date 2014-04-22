using System;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace Encryption
{
    public static class Helper
    {
        public static string GetDecryptedMessage(string authentication, string token, string apiCall)
        {
            var apiXmlDocument = new XmlDocument();
            string decryptedInfo;

            apiXmlDocument.Load(Constants.ApiXmlSheetLink);

            XmlNodeList infoNodeList = apiXmlDocument.SelectNodes("/api/call");
            XmlNode infoNode = null;
            foreach (XmlNode node in infoNodeList)
            {
                if (node.Attributes["name"].Value == apiCall)
                {
                    infoNode = node;
                }
            }
            var serializer = new XmlSerializer(typeof(ApiInfo));
            ApiInfo info = serializer.Deserialize(new StringReader(infoNode.OuterXml)) as ApiInfo;

            string serverAuthentication = ApiAuthentication.Encode(info.PublicKey, info.HashValue);

            if (String.CompareOrdinal(serverAuthentication, authentication) == 0)
            {
                decryptedInfo = ApiEncryption.Decrypt(token, serverAuthentication);
            }
            else
            {
                throw new DecryptionFailureException("unable to authenticate client");
            }
            return decryptedInfo;
        }

        public static string[] GetMessageParts(string message)
        {
            return message.Split('&');
        }
    }

    public class DecryptionFailureException : Exception
    {
        public DecryptionFailureException(string message)
            : base(message)
        {
        }
    }
}
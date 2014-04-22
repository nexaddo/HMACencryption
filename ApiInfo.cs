using System.Xml.Serialization;

namespace Encryption
{
    [XmlRoot("call")]
    public class ApiInfo
    {
        [XmlAttribute("name")]
        public string ApiCallName { get; set; }

        [XmlAttribute("public")]
        public string PublicKey { get; set; }

        [XmlAttribute("value")]
        public int HashValue { get; set; }

        [XmlText]
        public string ApiCall { get; set; }
    }
}
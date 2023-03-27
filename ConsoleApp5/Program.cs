using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp5
{

    internal class Program
    {
        public static string Encrypt(string plainText, RSACryptoServiceProvider rsa)
        {
            var data = Encoding.UTF8.GetBytes(plainText);
            var cypher = rsa.Encrypt(data, false);
            return Convert.ToBase64String(cypher);
        }

        static void Main(string[] args)
        {
            string data = "4413280046925120";
            var path = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);

            Console.WriteLine("Searching for *.pem file...");
            var files = Directory.GetFiles(path).Where(f => f.EndsWith(".pem"));

            var filePath = files.First();
            Console.WriteLine(filePath);

            var file = File.ReadAllBytes(filePath);

            var fileAsByteArray = Convert.ToBase64String(file);
            Console.WriteLine(fileAsByteArray);

            var fileAsStr = Encoding.UTF8.GetString(Convert.FromBase64String(fileAsByteArray));
            Console.WriteLine(fileAsStr);

            var test = Encoding.UTF8.GetBytes(fileAsStr);
            RSACryptoServiceProvider RSApublicKey = ImportPublicKey(fileAsStr);

            var encrypt = Encrypt(data, RSApublicKey);
            Console.WriteLine(encrypt);
           
        }
        public static RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);
            return csp;
        }

    }
}

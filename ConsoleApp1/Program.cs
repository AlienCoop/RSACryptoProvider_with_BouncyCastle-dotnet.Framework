using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Serialization;

public class RSACryptoExample
{
    public static void Main()
    {
        try
        {
              string pblkey =  @"-----BEGIN PUBLIC KEY-----" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvf2VUMkuNsqjwOsg8eLsLME" +
"ZPwDtj3lh3WUgtVN34Up9iP+VcMFBds2s0C+ecrTAaFXkswjCCRrhhZvn1yI1NyM7jB1NjQzN2WREOERtB87QHRkoNkEvNJT" +
"ne4zUg/1scnPCd7xcfX0Ut3tO0YmyOs5mqszgykxBpiJ5bxCs/DXGUx1SYl52AY6O01htyg1tSovVNEa2E7h+fCztBZHcCBM" +
"w96jMtmBcA9X+LAxlhBeXVmwSUQwDxKq4fLrIdkLl6TCuPRgJeI+4gO+zVdECj0PW0hq9J/E3dqGrYNeVL7zAa9lDYpwcBHc" +
"ARFtCKs76vcK9B/YkfGCohg7YJ9JfTwIDAQAB\n" +
             "-----END PUBLIC KEY-----";

            var PublicKey = Encoding.UTF8.GetBytes(pblkey);
            //initialze the byte arrays to the public key information.

            string number = "4413280046925120";
            //Values to store encrypted symmetric keys.
            //byte[] EncryptedSymmetricKey;
            //byte[] EncryptedSymmetricIV;

            //Create a new instance of RSACryptoServiceProvider.
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

            //Get an instance of RSAParameters from ExportParameters function.
            RSAParameters RSAKeyInfo = rsa.ExportParameters(false);
            
            //Set RSAKeyInfo to the public key values.
            RSAKeyInfo.Modulus = PublicKey;
            UTF8Encoding byteConverter = new UTF8Encoding();

            //Import key parameters into RSA.
            rsa.ImportParameters(RSAKeyInfo);


            Console.WriteLine(GetPublicKey(RSAKeyInfo).ToString());

            byte[] encBytes = RSAEncrypt(byteConverter.GetBytes(number), RSAKeyInfo, false);
            string encrypt = Convert.ToBase64String(encBytes);
            Console.WriteLine("Encrypt str: " + encrypt);

            Console.WriteLine('\n');
            Console.WriteLine(Encrypt(number, rsa));

        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }

        string Encrypt(string plainText, RSACryptoServiceProvider rsa)
        {
           
            var data = Encoding.UTF8.GetBytes(plainText);
            var cypher = rsa.Encrypt(data, false);
            return Convert.ToBase64String(cypher);
        }

    }
    static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        //Create a new instance of RSACryptoServiceProvider.
        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

        //Import the RSA Key information. This only needs
        //toinclude the public key information.
        RSA.ImportParameters(RSAKeyInfo);

        //Encrypt the passed byte array and specify OAEP padding.  
        //OAEP padding is only available on Microsoft Windows XP or
        //later.  
        return RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
    }
    public static string Encrypt(string plainText, RSACryptoServiceProvider rsa)
    {
        var data = Convert.FromBase64String(plainText);
        var cypher = rsa.Encrypt(data, false);
        return Convert.ToBase64String(cypher);
    }
    public static string GetPublicKey(RSAParameters rSAParameters)
    {
        var sw = new StringWriter();
        var xs = new XmlSerializer(typeof(RSAParameters));
        xs.Serialize(sw, rSAParameters);

        return sw.ToString();
    }

}
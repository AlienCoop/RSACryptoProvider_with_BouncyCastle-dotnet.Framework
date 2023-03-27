using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class CardCryptoHelper
{

    //public static byte[] GetBytesFromString(string someString)
    //{
    //    return Convert.FromBase64String(someString);
    //}
    public static string Encrypt(string plainText, RSACryptoServiceProvider rsa)
    {
        var data = Encoding.UTF8.GetBytes(plainText);
        var cypher = rsa.Encrypt(data, false);
        return Convert.ToBase64String(cypher);
    }
    public static void Main()
    {
        string publicKey = @"-----BEGIN PUBLIC KEY-----" +
                      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvf2VUMkuNsqjwOsg8eLsLME" +
        "ZPwDtj3lh3WUgtVN34Up9iP+VcMFBds2s0C+ecrTAaFXkswjCCRrhhZvn1yI1NyM7jB1NjQzN2WREOERtB87QHRkoNkEvNJT" +
        "ne4zUg/1scnPCd7xcfX0Ut3tO0YmyOs5mqszgykxBpiJ5bxCs/DXGUx1SYl52AY6O01htyg1tSovVNEa2E7h+fCztBZHcCBM" +
        "w96jMtmBcA9X+LAxlhBeXVmwSUQwDxKq4fLrIdkLl6TCuPRgJeI+4gO+zVdECj0PW0hq9J/E3dqGrYNeVL7zAa9lDYpwcBHc" +
        "ARFtCKs76vcK9B/YkfGCohg7YJ9JfTwIDAQAB\n" +
                       "-----END PUBLIC KEY-----";
        var someData = "4413280046925120";
        var rsa = new RSACryptoServiceProvider();
        rsa.ImportFromPem(publicKey.ToCharArray());
        //var bytedData = GetBytesFromString(someData);

        var test = Encrypt(someData, rsa);
        Console.WriteLine(test);
    }
}


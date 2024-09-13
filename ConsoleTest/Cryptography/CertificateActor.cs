using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ConsoleTest.Cryptography;

/// <summary>
/// Based on example from: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=net-8.0
/// </summary>
public class CertificateActor : IActor
{
    /// <summary>
    /// Create X509Certificate2 object from .cer file.
    /// </summary>
    public CertificateActor(string dataFilePath)
    {
        var rawData = File.ReadAllBytes(dataFilePath);
        X509 = new X509Certificate2(rawData);
    }

    public CertificateActor(byte[] rawData)
    {
        X509 = new X509Certificate2(rawData);
    }

    X509Certificate2 X509 { get; set; }

    RSA RsaPublicKey
    {
        get
        {
            var publicKey = X509.GetRSAPublicKey();
            if (publicKey == null)
            {
                throw new SystemException("Certificate missing RSA public key");
            }

            return publicKey;
        }
    }

    public void PrintInformationToConsole()
    {
        Console.WriteLine("Subject: {0}.", X509.Subject);
        Console.WriteLine("Issuer: {0}.", X509.Issuer);
        Console.WriteLine("Version: {0}.", X509.Version);
        Console.WriteLine("Valid Date: {0}.", X509.NotBefore);
        Console.WriteLine("Expiry Date: {0}.", X509.NotAfter);
        Console.WriteLine("Thumbprint: {0}.", X509.Thumbprint);
        Console.WriteLine("Serial Number: {0}.", X509.SerialNumber);
        Console.WriteLine("Friendly Name: {0}.", X509.PublicKey.Oid.FriendlyName);
        Console.WriteLine("Public Key Format: {0}.", X509.PublicKey.EncodedKeyValue.Format(true));
        Console.WriteLine("Raw Data Length: {0}.", X509.RawData.Length);
        Console.WriteLine("Certificate to string: {0}.", X509.ToString(true));
        Console.WriteLine("Certificate to XML String: {0}.", X509.GetRSAPublicKey()?.ToXmlString(false));
    }

    public byte[] EncryptData(byte[] data)
    {
		using var inStream = new MemoryStream(data);
		using var outStream = new MemoryStream(data.Length);
		
		RsaPublicKey.EncryptDataWithIntermediateAesKey(inStream, outStream);
		return outStream.ToArray();
    }

    public byte[] DecryptData(byte[] data)
    {
		throw new NotImplementedException("Public key shouldn't be used to decrypt message encrypted by private key");
	}

    public byte[] SignData(byte[] data)
    {
        return RsaPublicKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public bool VerifySignature(byte[] data, byte[] signature)
    {
        return RsaPublicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static byte[] ReadFile(string fileName)
    {
        using var fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read);
        int size = (int)fileStream.Length;
        byte[] data = new byte[size];
        size = fileStream.Read(data, 0, size);
        return data;
    }
}

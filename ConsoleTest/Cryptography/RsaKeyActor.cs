using System.Security.Cryptography;

namespace ConsoleTest.Cryptography;

/// <summary>
/// Base on URL: https://sjm.io/blog/rsa-file-signing/
/// </summary>
public class RsaKeyActor
{
    public RsaKeyActor(string rsaKeyFile)
    {
        RsaKey = RSA.Create();
        RsaKey.ImportFromPem(File.ReadAllText(rsaKeyFile).ToCharArray());
    }

    public RSA RsaKey { get; }

    public void PrintInformationToConsole()
    {
        Console.WriteLine("Key exchange algorithm: {0}.", RsaKey.KeyExchangeAlgorithm);
        Console.WriteLine("Key size: {0}.", RsaKey.KeySize);
        Console.WriteLine("Key signature algorithm: {0}.", RsaKey.SignatureAlgorithm);
        Console.WriteLine("Key to string: {0}.", RsaKey.ToString());
        Console.WriteLine("Key to XML String: {0}.", RsaKey.ToXmlString(false));
    }

    public byte[] EncryptData(byte[] data)
    {
        return RsaKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] DecryptData(byte[] data)
    {
        return RsaKey.Decrypt(data, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] SignData(byte[] data)
    {
        return RsaKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public bool VerifySignature(byte[] data, byte[] signature)
    {
        return RsaKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}

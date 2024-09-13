using System.Security.Cryptography;
using System.Text.Unicode;

namespace ConsoleTest.Cryptography;

public static class RsaCryptoExtensions
{
	/// <summary>
	/// As RSA Key is not suitable for encrypt large data (e.g. max encryption block is less then key length, not very fast),
	/// AES is used instead, where AES key will then be encrypted by the RSA
	/// </summary>
	public static void EncryptDataWithIntermediateAesKey(this RSA rsaKey, Stream inStream, Stream outStream)
	{
		using (var aes = Aes.Create())
		{
			// Create instance of Aes for symmetric encryption of the data.
			aes.KeySize = Math.Min(rsaKey.KeySize - 10, 256);
			aes.Mode = CipherMode.CBC;
			using (var transform = aes.CreateEncryptor())
			{
				var keyFormatter = new RSAPKCS1KeyExchangeFormatter(rsaKey);
				var keyEncrypted = keyFormatter.CreateKeyExchange(aes.Key, aes.GetType());

				int lKey = keyEncrypted.Length;
				var LenK = BitConverter.GetBytes(lKey);
				int lIV = aes.IV.Length;	// IV: Initialized Vector
				var LenIV = BitConverter.GetBytes(lIV);

				// Write the following to the Stream
				// for the encrypted file (outStream):
				// - length of the key
				// - length of the IV
				// - encrypted key
				// - the IV
				// - the encrypted cipher content
				outStream.Write(LenK, 0, 4);
				outStream.Write(LenIV, 0, 4);
				outStream.Write(keyEncrypted, 0, lKey);
				outStream.Write(aes.IV, 0, lIV);

				// Now write the cipher text using a CryptoStream for encrypting.
				using (var outStreamEncrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write))
				{

					// By encrypting a chunk at a time,
					// you can save memory and accommodate large files.
					var count = 0;

					// blockSizeBytes can be any arbitrary size.
					var blockSizeBytes = aes.BlockSize / 8;
					var data = new byte[blockSizeBytes];
					var bytesRead = 0;

					do
					{
						count = inStream.Read(data, 0, blockSizeBytes);
						outStreamEncrypted.Write(data, 0, count);
						bytesRead += count;
					}
					while (count > 0);

					outStreamEncrypted.FlushFinalBlock();
					outStreamEncrypted.Close();
				}
			}
		}
	}

	public static void DecryptDataWithIntermediateAesKey(this RSA rsaKey, Stream inStream, Stream outStream)
	{
		using (var aes = Aes.Create())
		{
			// Create instance of Aes for symmetric encryption of the data.
			aes.KeySize = Math.Min(rsaKey.KeySize - 10, 256);
			aes.Mode = CipherMode.CBC;

			// Create byte arrays to get the length of the encrypted key and IV.
			// These values were stored as 4 bytes each
			// at the beginning of the encrypted package.
			var LenK = new byte[4];
			var LenIV = new byte[4];

			inStream.Seek(0, SeekOrigin.Begin);
			inStream.Read(LenK, 0, 3);
			inStream.Seek(4, SeekOrigin.Begin);
			inStream.Read(LenIV, 0, 3);

			// Convert the lengths to integer values.
			int lenK = BitConverter.ToInt32(LenK, 0);
			int lenIV = BitConverter.ToInt32(LenIV, 0);

			// Create the byte arrays for the encrypted Aes key,
			// the IV, and the cipher text.
			var keyEncrypted = new byte[lenK];
			var keyInitializedVector = new byte[lenIV];

			// Extract the key and IV
			// starting from index 8 after the length values.
			inStream.Seek(8, SeekOrigin.Begin);
			inStream.Read(keyEncrypted, 0, lenK);
			inStream.Seek(8 + lenK, SeekOrigin.Begin);
			inStream.Read(keyInitializedVector, 0, lenIV);

			// Determine the start position of
			// the cipher text (startC) and its length(lenC).
			int startC = lenK + lenIV + 8;
			int lenC = (int)inStream.Length - startC;

			// Use RSA
			// to decrypt the Aes key.
			byte[] KeyDecrypted = rsaKey.Decrypt(keyEncrypted, RSAEncryptionPadding.Pkcs1);

			// Decrypt the key.
			using (ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, keyInitializedVector))
			{
				/*
				 * Decrypt the cipher text 
				 * from the Steam of the encrypted (inStream)
				 * into the Stream for the decrypted (outStream)
				*/

				// By decrypting a chunk a time,
				// you can save memory and  accommodate large files.
				var blockSizeBytes = aes.BlockSize / 8;
				var dataBuffer = new byte[blockSizeBytes];


				// Start at the beginning
				// of the cipher text.
				inStream.Seek(startC, SeekOrigin.Begin);
				using (CryptoStream outStreamDecrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write))
				{
					var count = 0;
					do
					{
						count = inStream.Read(dataBuffer, 0, blockSizeBytes);
						outStreamDecrypted.Write(dataBuffer, 0, count);
					}
					while (count > 0);

					outStreamDecrypted.FlushFinalBlock();
					outStreamDecrypted.Close();
				}

			}
		}
	}
}

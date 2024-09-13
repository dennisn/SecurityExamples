using System.Text;

namespace ConsoleTest
{
	internal class ProgramMain
	{
		static readonly string BaseDir = @"C:\WTG\IL\WI00793348_CargoVisibilityAPI_SetupS2ST\01_CertificateSigningRequest";

		static readonly string CertificateFile = $"{BaseDir}/WTG_ILS_CargoVisibilityAPI.cer";
		static readonly string PublicKeyFile = $"{BaseDir}/public_key.pem";
		static readonly string PrivateKeyFile = $"{BaseDir}/private_key.pem";

		static readonly string TestDataFile = $"{BaseDir}/TestData_ZIMUFLX09069253.json";

		static void Main(string[] args)
		{
			if (args.Length < 1)
			{
				Console.WriteLine("Missing arguments: <ProgramName> <Command> <CommandArguments...>");
				return;
			}

			Console.WriteLine("Arguments: {0}", string.Join(',', args));
			switch (args[0].ToLowerInvariant())
			{
				case "print_certificate":
					PrintCertificate(CertificateFile);
					return;
				case "print_public_pem":
					PrintRsaKey(PublicKeyFile);
					return;
				case "print_private_pem":
					PrintRsaKey(PrivateKeyFile);
					return;
				case "print_all":
					var lineSep = new string('-', 20);

					Console.WriteLine(lineSep);
					PrintCertificate(CertificateFile);

					Console.WriteLine(lineSep);
					PrintRsaKey(PublicKeyFile);

					Console.WriteLine(lineSep);
					PrintRsaKey(PrivateKeyFile);
					return;
				case "encrypt_by_cert":
					{
						var certificateActor = new CertificateActor(CertificateFile);
						var privateKeyActor = new RsaKeyActor(PrivateKeyFile);

						var rawData = File.ReadAllBytes(TestDataFile);
						var encryptedData = certificateActor.EncryptData(rawData);
						var decryptedData = privateKeyActor.DecryptData(encryptedData);
						Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
					}
					return;
				case "sign_by_private":
					{
						var certificateActor = new CertificateActor(CertificateFile);
						var privateKeyActor = new RsaKeyActor(PrivateKeyFile);

						var rawData = File.ReadAllBytes(TestDataFile);
						var signature = privateKeyActor.SignData(rawData);
						var verifyResult = certificateActor.VerifySignature(rawData, signature);

						Console.WriteLine("Verify result: {0} with signature {1}", verifyResult, Convert.ToBase64String(signature));
					}
					return;
				default:
					Console.WriteLine($"Invalid command: {args[0]}");
					return;
			}
		}

		static void PrintCertificate(string filePath)
		{
			var certificateActor = new CertificateActor(filePath);
			certificateActor.PrintInformationToConsole();
		}

		static void PrintRsaKey(string filePath)
		{
			var rsaKeyActor = new RsaKeyActor(filePath);
			rsaKeyActor.PrintInformationToConsole();
		}
	}
}

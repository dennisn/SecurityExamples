namespace ConsoleTest;

public interface IActor
{
	void PrintInformationToConsole();

	byte[] EncryptData(byte[] data);

	byte[] DecryptData(byte[] data);

	byte[] SignData(byte[] data);

	bool VerifySignature(byte[] data, byte[] signature);
}

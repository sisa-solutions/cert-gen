using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace Sisa.Security.Helpers;

public static class ExportCertificateHelper
{
    private static string OutFolder { get; } = "gen";

    public static async Task ExportPfxAsync([NotNull] X509Certificate2 certificate, string filePath, string password)
    {
        byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

        await File.WriteAllBytesAsync(filePath, pfxBytes);

        Console.WriteLine("Certificate exported to {0}.", filePath);
    }

    public static async Task ExportCertificatePemAsync([NotNull] X509Certificate2 certificate, string filePath)
    {
        await File.WriteAllTextAsync(filePath, certificate.ExportCertificatePem());

        Console.WriteLine("Certificate exported to {0}.", filePath);
    }

    public static async Task ExportRsaPrivateKeyPemAsync([NotNull] X509Certificate2 certificate, string filePath)
    {
        await File.WriteAllTextAsync(filePath, certificate.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem());

        Console.WriteLine("RSA private key exported to {0}.", filePath);
    }

    public static async Task ExportRsaPublicKeyPemAsync([NotNull] X509Certificate2 certificate, string filePath)
    {
        await File.WriteAllTextAsync(filePath, certificate.GetRSAPublicKey()!.ExportRSAPublicKeyPem());

        Console.WriteLine("RSA public key exported to {0}.", filePath);
    }

    public static async Task ExportEcdsaPrivateKeyPemAsync([NotNull] X509Certificate2 certificate, string filePath)
    {
        await File.WriteAllTextAsync(filePath, certificate.GetECDsaPrivateKey()!.ExportECPrivateKeyPem());

        Console.WriteLine("ECDSA private key exported to {0}.", filePath);
    }

    public static string GetExistingFilePath(string fileName)
    {
        string currentDirectory = Environment.CurrentDirectory;

        string filePath = Path.Combine(currentDirectory, OutFolder, fileName);

        return filePath;
    }

    public static void EnsureOutFolderExists()
    {
        string currentDirectory = Environment.CurrentDirectory;

        string outFolderPath = Path.Combine(currentDirectory, OutFolder);

        if (!Directory.Exists(outFolderPath))
        {
            Console.WriteLine("Creating output folder {0}.", outFolderPath);

            Directory.CreateDirectory(outFolderPath);
        }
    }

    public static string BuildExportFilePath([NotNull] string fileName)
    {
        string currentDirectory = Environment.CurrentDirectory;

        string filePath = Path.Combine(currentDirectory, OutFolder, fileName);

        int i = 1;

        while (File.Exists(filePath))
        {
            filePath = Path.Combine(currentDirectory, OutFolder, fileName.Replace(".", $"-{i}.", StringComparison.OrdinalIgnoreCase));
            i++;
        }

        return filePath;
    }
}

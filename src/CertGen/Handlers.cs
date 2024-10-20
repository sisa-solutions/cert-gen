using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Sisa.Security.Helpers;

namespace Sisa.Security;

public static class CommandHandler
{
    private static readonly string RootCAName = "root-ca";
    private static readonly string RootCACommonName = "Sisa Development Root CA";

    public static Command Initialize()
    {
        #region Global options

        var certNameOption = new Option<string>(
            name: "--name",
            description: "Certificate name, the output files name with have the format {name}-{ecdsa|rsa}-key.pem, {name}-{ecdsa|rsa}-cert.pem, {name}-{ecdsa|rsa}-cert.pfx"
        )
        {
            IsRequired = true,
        };
        certNameOption.AddAlias("-n");

        var algorithmOption = new Option<Algorithm>(
            name: "--algorithm",
            description: "Hash algorithm",
            getDefaultValue: () => Algorithm.SHA256
        )
        {
            IsRequired = false,
        };

        algorithmOption.AddAlias("-a");

        var dnsNamesOption = new Option<string[]>(
            name: "--dns-names",
            description: "DNS names for the certificate",
            getDefaultValue: () => ["localhost"]
        )
        {
            IsRequired = false,
        };
        dnsNamesOption.AddAlias("-d");

        var pfxPasswordOption = new Option<string?>(
            name: "--pfx-password",
            description: "Password for PFX export, if not provided, PFX export will be skipped"
        )
        {
            IsRequired = false,
        };
        pfxPasswordOption.AddAlias("-p");

        var organizationNameOption = new Option<string?>(
            name: "--organization-name",
            description: "Organization name",
            getDefaultValue: () => "Sisa Solutions"
        )
        {
            IsRequired = false,
        };

        organizationNameOption.AddAlias("-o");

        var organizationUnitNameOption = new Option<string?>(
            name: "--organization-unit-name",
            description: "Organization unit name",
            getDefaultValue: () => $"{Environment.UserName}@{Environment.UserDomainName}"
        )
        {
            IsRequired = false,
        };

        organizationUnitNameOption.AddAlias("-ou");

        var commonNameOption = new Option<string?>(
            name: "--common-name",
            description: "Common name",
            getDefaultValue: () => "Sisa Development"
        )
        {
            IsRequired = false,
        };

        commonNameOption.AddAlias("-cn");

        #endregion

        #region Root Command

        var rootCommand = new RootCommand(
            description: "Sisa Development Certificate Generator"
        );

        rootCommand.AddGlobalOption(certNameOption);
        rootCommand.AddGlobalOption(algorithmOption);
        rootCommand.AddGlobalOption(dnsNamesOption);
        rootCommand.AddGlobalOption(pfxPasswordOption);
        rootCommand.AddGlobalOption(organizationNameOption);
        rootCommand.AddGlobalOption(organizationUnitNameOption);
        rootCommand.AddGlobalOption(commonNameOption);

        #endregion

        # region Create ECDSA subcommand

        var ecdsaCurveOption = new Option<NamedCurve>(
            name: "--curve",
            description: "Named curve for the ECDSA key pair",
            getDefaultValue: () => NamedCurve.nistP256
        )
        {
            IsRequired = false,
        };

        ecdsaCurveOption.AddAlias("-c");

        var createEcdsaSubCommand = new Command(
            name: "ecdsa",
            description: "Generate Certificate with ECDSA key pair"
        ) {
            ecdsaCurveOption
        };

        createEcdsaSubCommand.SetHandler(
            CreateEcdsaCommandHandleAsync,
            new CreateEcdsaCommandOptionsBinder(
                certNameOption,
                algorithmOption,
                ecdsaCurveOption,
                dnsNamesOption,
                pfxPasswordOption,
                organizationNameOption,
                organizationUnitNameOption,
                commonNameOption
            )
        );

        rootCommand.Add(createEcdsaSubCommand);

        #endregion

        #region Create RSA subcommand

        var rsaKeySizeOption = new Option<int>(
            name: "--key-size",
            description: "RSA key size in bits",
            getDefaultValue: () => 2048
        )
        {
            IsRequired = false,
        };
        rsaKeySizeOption.AddAlias("-s");

        var createRsaSubCommand = new Command(
            name: "rsa",
            description: "Generate Certificate with RSA key pair"
        ) {
            rsaKeySizeOption,
        };

        createRsaSubCommand.SetHandler(
            CreateRsaCommandHandleAsync,
            new CreateRsaCommandOptionsBinder(
                certNameOption,
                algorithmOption,
                rsaKeySizeOption,
                dnsNamesOption,
                pfxPasswordOption,
                organizationNameOption,
                organizationUnitNameOption,
                commonNameOption
            )
        );

        rootCommand.Add(createRsaSubCommand);

        #endregion

        return rootCommand;
    }

    private static async Task CreateEcdsaCommandHandleAsync(CreateEcdsaCommandOptions options)
    {
        string rootCaFilePath = ExportCertificateHelper.GetExistingFilePath($"{RootCAName}-ecdsa-cert.pem");
        string rootCaKeyFilePath = ExportCertificateHelper.GetExistingFilePath($"{RootCAName}-ecdsa-key.pem");

        bool isRootCaExists = File.Exists(rootCaFilePath) && File.Exists(rootCaKeyFilePath);

        X509Certificate2? rootCa;

        if (isRootCaExists)
        {
            Console.WriteLine("Root CA exists");
            Console.WriteLine("Loading root CA certificate");

            rootCa = GenerateSslHelper.LoadRootCACertificate(rootCaFilePath, rootCaKeyFilePath);

            if (rootCa == null)
            {
                await Console.Error.WriteLineAsync("Failed to load root CA certificate");

                return;
            }
        }
        else
        {
            var caSubjectName = GenerateSslHelper.BuildSubjectName(options.OrganizationName!, options.OrganizationUnitName!, RootCACommonName);
            rootCa = GenerateSslHelper.CreateEcdsaRootCACertificate(caSubjectName);
        }

        HashAlgorithmName hashAlgorithm = GenerateSslHelper.GetHashAlgorithm(options.Algorithm);

        var certSubjectName = GenerateSslHelper.BuildSubjectName(options.OrganizationName!, options.OrganizationUnitName!, options.CommonName!);
        var cert = GenerateSslHelper.CreateEcdsaSelfSignCertificate(
            rootCa,
            certSubjectName,
            hashAlgorithm,
            options.NamedCurve,
            options.DnsNames
        );

        ExportCertificateHelper.EnsureOutFolderExists();

        List<Task> tasks = [];

        if (!isRootCaExists)
        {
            tasks.AddRange([
                ExportCertificateHelper.ExportEcdsaPrivateKeyPemAsync(rootCa, rootCaKeyFilePath),
                ExportCertificateHelper.ExportCertificatePemAsync(rootCa, rootCaFilePath)
            ]);
        }

        string keyFilePath = ExportCertificateHelper.BuildExportFilePath($"{options.CertName}-ecdsa-key.pem");
        string certFilePath = ExportCertificateHelper.BuildExportFilePath($"{options.CertName}-ecdsa-cert.pem");

        tasks.AddRange([
            ExportCertificateHelper.ExportEcdsaPrivateKeyPemAsync(cert, keyFilePath),
            ExportCertificateHelper.ExportCertificatePemAsync(cert, certFilePath),
        ]);

        if (!string.IsNullOrWhiteSpace(options.PfxPassword))
        {
            string pfxFilePath = $"{options.CertName}-ecdsa-cert.pfx";

            tasks.Add(ExportCertificateHelper.ExportPfxAsync(cert, pfxFilePath, options.PfxPassword));
        }

        await Task.WhenAll(tasks);
    }

    private static async Task CreateRsaCommandHandleAsync(CreateRsaCommandOptions options)
    {
        string rootCaFilePath = ExportCertificateHelper.GetExistingFilePath($"{RootCAName}-rsa-cert.pem");
        string rootCaKeyFilePath = ExportCertificateHelper.GetExistingFilePath($"{RootCAName}-rsa-key.pem");

        bool isRootCaExists = File.Exists(rootCaFilePath) && File.Exists(rootCaKeyFilePath);

        X509Certificate2? rootCa;

        if (isRootCaExists)
        {
            Console.WriteLine("Root CA exists");
            Console.WriteLine("Loading root CA certificate");

            rootCa = GenerateSslHelper.LoadRootCACertificate(rootCaFilePath, rootCaKeyFilePath);

            if (rootCa == null)
            {
                await Console.Error.WriteLineAsync("Failed to load root CA certificate");

                return;
            }
        }
        else
        {
            Console.WriteLine("Root CA does not exist");
            Console.WriteLine("Creating root CA certificate");

            var caSubjectName = GenerateSslHelper.BuildSubjectName(options.OrganizationName!, options.OrganizationUnitName!, RootCACommonName);
            rootCa = GenerateSslHelper.CreateRsaRootCACertificate(caSubjectName);
        }

        HashAlgorithmName hashAlgorithm = GenerateSslHelper.GetHashAlgorithm(options.Algorithm);
        var certSubjectName = GenerateSslHelper.BuildSubjectName(options.OrganizationName!, options.OrganizationUnitName!, options.CommonName!);

        Console.WriteLine("Creating self-signed certificate");
        var cert = GenerateSslHelper.CreateRsaSelfSignCertificate(
            rootCa,
            certSubjectName,
            hashAlgorithm,
            options.KeySize,
            options.DnsNames
        );

        ExportCertificateHelper.EnsureOutFolderExists();

        var keyFileName = $"{options.CertName}-rsa-key.pem";
        var certFileName = $"{options.CertName}-rsa-key.pem";

        List<Task> tasks = [];

        if (!isRootCaExists)
        {
            tasks.AddRange([
                ExportCertificateHelper.ExportRsaPrivateKeyPemAsync(rootCa, rootCaKeyFilePath),
                ExportCertificateHelper.ExportCertificatePemAsync(rootCa, rootCaFilePath)
            ]);
        }

        string keyFilePath = ExportCertificateHelper.BuildExportFilePath(keyFileName);
        string certFilePath = ExportCertificateHelper.BuildExportFilePath(certFileName);

        Console.WriteLine("Exporting certificate and private key");

        tasks.AddRange([
            ExportCertificateHelper.ExportRsaPrivateKeyPemAsync(cert, keyFilePath),
            ExportCertificateHelper.ExportCertificatePemAsync(cert, certFilePath),
        ]);

        if (!string.IsNullOrWhiteSpace(options.PfxPassword))
        {
            string pfxFilePath = $"{options.CertName}-rsa-cert.pfx";
            pfxFilePath = ExportCertificateHelper.BuildExportFilePath(pfxFilePath);

            tasks.Add(ExportCertificateHelper.ExportPfxAsync(cert, pfxFilePath, options.PfxPassword));
        }

        await Task.WhenAll(tasks);
    }
}

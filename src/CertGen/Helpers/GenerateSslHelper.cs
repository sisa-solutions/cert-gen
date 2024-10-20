using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sisa.Security.Helpers;

public static class GenerateSslHelper
{
    public static X509Certificate2? LoadRootCACertificate(string certPath, string keyPath)
    {
        try
        {
            var cert = X509Certificate2.CreateFromPemFile(certPath, keyPath);

            return cert;
        }
        catch
        {
            return null;
        }
    }

    public static X509Certificate2 CreateEcdsaRootCACertificate(string subjectName)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        CertificateRequest certificateRequest = new(subjectName, key, HashAlgorithmName.SHA512);

        return CreateRootCACertificate(certificateRequest);
    }

    public static X509Certificate2 CreateRsaRootCACertificate(string subjectName)
    {
        using RSA key = RSA.Create(4096);
        CertificateRequest certificateRequest = new(subjectName, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        return CreateRootCACertificate(certificateRequest);
    }

    public static X509Certificate2 CreateEcdsaSelfSignCertificate(X509Certificate2 issuerCertificate, string subjectName, HashAlgorithmName hashAlgorithm, NamedCurve namedCurve, string[] dnsNames)
    {
        var curve = namedCurve switch
        {
            NamedCurve.nistP384 => ECCurve.NamedCurves.nistP384,
            NamedCurve.nistP521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256,
        };

        using ECDsa key = ECDsa.Create(curve);
        CertificateRequest certificateRequest = new(subjectName, key, hashAlgorithm);

        var signedCert = CreateSelfSignCertificate(issuerCertificate, certificateRequest, dnsNames);

        return signedCert.CopyWithPrivateKey(key);
    }

    public static X509Certificate2 CreateRsaSelfSignCertificate(X509Certificate2 issuerCertificate, string subjectName, HashAlgorithmName hashAlgorithm, int keySize, string[] dnsNames)
    {
        using RSA key = RSA.Create(keySize);
        CertificateRequest certificateRequest = new(subjectName, key, hashAlgorithm, RSASignaturePadding.Pkcs1);

        var signedCert = CreateSelfSignCertificate(issuerCertificate, certificateRequest, dnsNames);

        return signedCert.CopyWithPrivateKey(key);
    }

    # region Private Methods

    private static X509Certificate2 CreateRootCACertificate(CertificateRequest certificateRequest)
    {
        DateTimeOffset currentDate = DateTimeOffset.UtcNow;

        // Add Key Usage for CA (KeyCertSign)
        certificateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                keyUsages: X509KeyUsageFlags.KeyCertSign,
                critical: true
            )
        );

        // Add Basic Constraints for CA
        certificateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 0,
                critical: true
            )
        );

        // Add Subject Key Identifier
        certificateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, critical: false));

        var certificate = certificateRequest.CreateSelfSigned(currentDate.AddDays(-1), currentDate.AddYears(10));

        return certificate;
    }

    private static X509Certificate2 CreateSelfSignCertificate(X509Certificate2 issuerCertificate, CertificateRequest certificateRequest, string[] dnsNames)
    {
        DateTimeOffset currentDate = DateTimeOffset.UtcNow;

        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: true,
            pathLengthConstraint: 0,
            critical: false
        ));

        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true
        ));

        // 1.3.6.1.5.5.7.3.1        OID for Server Authentication
        // 1.3.6.1.5.5.7.3.2        OID for Client Authentication
        // 1.3.6.1.5.5.7.3.3        Code Signing
        // 1.3.6.1.5.5.7.3.4        Email Protection
        // 1.3.6.1.5.5.7.3.8        Time Stamping

        var enhancedKeyUsage = new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.1"), // Server Authentication
        };
        certificateRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(enhancedKeyUsage, critical: false));

        var authorityKeyIdentifierExtension = X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            issuerCertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false);

        certificateRequest.CertificateExtensions.Add(authorityKeyIdentifierExtension);

        var sanBuilder = new SubjectAlternativeNameBuilder();

        foreach (var dnsName in dnsNames)
        {
            sanBuilder.AddDnsName(dnsName);
        }

        certificateRequest.CertificateExtensions.Add(sanBuilder.Build(critical: false));
        // Sign the certificate using the CA's private key
        Span<byte> serialNumber = stackalloc byte[8];
        RandomNumberGenerator.Fill(serialNumber);

        X509Certificate2 signedCert = certificateRequest.Create(
            issuerCertificate,
            currentDate.AddDays(-1),
            currentDate.AddYears(3),
            serialNumber
        );

        return signedCert;
    }

    #endregion

    public static string BuildSubjectName(string organizationName, string organizationUnitName, string commonName)
    {
        return $"O={organizationName}, OU={organizationUnitName}, CN={commonName}";
    }

    public static HashAlgorithmName GetHashAlgorithm(Algorithm algorithm)
    {
        return algorithm switch
        {
            Algorithm.SHA384 => HashAlgorithmName.SHA384,
            Algorithm.SHA512 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
    }
}

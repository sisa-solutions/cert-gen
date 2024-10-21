using System.CommandLine;
using System.CommandLine.Binding;
using System.Diagnostics.CodeAnalysis;

namespace Sisa.Security;

public record GlobalOptions
{
    public string CertName { get; set; } = null!;

    public Algorithm Algorithm { get; set; }

    public IReadOnlyCollection<string> DnsNames { get; set; } = [];
    public string? PfxPassword { get; set; }

    public string? OrganizationName { get; set; }

    public string? OrganizationUnitName { get; set; }

    public string? CommonName { get; set; }

}

public abstract class GlobalOptionsBinder<TOptions>(
    Option<string> certName,
    Option<Algorithm> algorithm,
    Option<IReadOnlyCollection<string>> dnsNames,
    Option<string?> pfxPassword,
    Option<string?> organizationName,
    Option<string?> organizationUnitName,
    Option<string?> commonName
) : BinderBase<TOptions>
    where TOptions : GlobalOptions, new()
{
    protected override TOptions GetBoundValue([NotNull] BindingContext bindingContext) =>
        new()
        {
            CertName = bindingContext.ParseResult.GetValueForOption(certName)!,
            Algorithm = bindingContext.ParseResult.GetValueForOption(algorithm),
            DnsNames = bindingContext.ParseResult.GetValueForOption(dnsNames) ?? [],
            PfxPassword = bindingContext.ParseResult.GetValueForOption(pfxPassword),
            OrganizationName = bindingContext.ParseResult.GetValueForOption(organizationName),
            OrganizationUnitName = bindingContext.ParseResult.GetValueForOption(organizationUnitName),
            CommonName = bindingContext.ParseResult.GetValueForOption(commonName)
        };
}

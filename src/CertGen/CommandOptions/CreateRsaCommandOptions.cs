using System.CommandLine;
using System.CommandLine.Binding;
using System.Diagnostics.CodeAnalysis;

namespace Sisa.Security;

public sealed record CreateRsaCommandOptions : GlobalOptions
{
    public int KeySize { get; set; } = 2048;
}

public sealed class CreateRsaCommandOptionsBinder(
    Option<string> certName,
    Option<Algorithm> algorithm,
    Option<int> keySize,
    Option<string[]> dnsNames,
    Option<string?> pfxPassword,
    Option<string?> organizationName,
    Option<string?> organizationUnitName,
    Option<string?> commonName
) : GlobalOptionsBinder<CreateRsaCommandOptions>(
    certName,
    algorithm,
    dnsNames,
    pfxPassword,
    organizationName,
    organizationUnitName,
    commonName
)
{
    protected override CreateRsaCommandOptions GetBoundValue([NotNull
    ] BindingContext bindingContext) =>
        base.GetBoundValue(bindingContext) with
        {
            KeySize = bindingContext.ParseResult.GetValueForOption(keySize)
        };
}

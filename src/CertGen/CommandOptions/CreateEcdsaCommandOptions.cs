using System.CommandLine;
using System.CommandLine.Binding;
using System.Diagnostics.CodeAnalysis;

namespace Sisa.Security;

public record CreateEcdsaCommandOptions : GlobalOptions
{
    public NamedCurve NamedCurve { get; set; } = NamedCurve.nistP256;
}

public sealed class CreateEcdsaCommandOptionsBinder(
    Option<string> certName,
    Option<Algorithm> algorithm,
    Option<NamedCurve> namedCurve,
    Option<IReadOnlyCollection<string>> dnsNames,
    Option<string?> pfxPassword,
    Option<string?> organizationName,
    Option<string?> organizationUnitName,
    Option<string?> commonName
) : GlobalOptionsBinder<CreateEcdsaCommandOptions>(
    certName,
    algorithm,
    dnsNames,
    pfxPassword,
    organizationName,
    organizationUnitName,
    commonName
)
{
    protected override CreateEcdsaCommandOptions GetBoundValue([NotNull] BindingContext bindingContext) =>
        base.GetBoundValue(bindingContext) with
        {
            NamedCurve = bindingContext.ParseResult.GetValueForOption(namedCurve)
        };
}

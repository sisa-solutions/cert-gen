using System.CommandLine;

using Sisa.Security;

await CommandHandler.Initialize()
    .InvokeAsync(args);

// For Linux, run the following commands to install the root CA certificate
// sudo cp root-ca-cert.pem /usr/local/share/ca-certificates/root-ca-cert.crt
// sudo update-ca-certificates --fresh

// For Windows, double-click on root-ca-cert.pem and install to Trusted Root Certification Authorities

// For macOS, double-click on root-ca-cert.pem and install to System keychain

// For Chrome, go to chrome://settings/certificates
// Import root-ca-cert.pem to Authorities

// For Edge, go to edge://settings/certificates
// Import root-ca-cert.pem to Trusted Root Certification Authorities

// For Firefox, go to about:preferences#privacy
// View Certificates -> Authorities -> Import

// For Safari, go to Preferences -> Privacy -> Manage Website Data

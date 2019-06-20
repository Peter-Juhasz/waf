using Microsoft.AspNetCore.Http;
using System;
using System.Threading;

namespace Firewall
{
    internal sealed class ScannerInspector : IRequestInspector
    {
        private static readonly Rule Rule = new Rule("P001", WellKnownCategories.Protocol, "Protocol Violation");

        public void Inspect(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Request.Headers.ContainsKey("X-Scanner"))
            {
                context.ReportDiagnostic(new Diagnostic(Rule, Location.RequestHeader("X-Scanner")));
            }
        }
    }
}

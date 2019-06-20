using Microsoft.AspNetCore.Http;
using System;
using System.Threading;

namespace Firewall
{
    internal sealed class ProtocolEnforcementInspector : IRequestInspector
    {
        private static readonly Rule Rule = new Rule("P001", WellKnownCategories.Protocol, "Protocol Violation");
        private static readonly Rule RuleTrace = new Rule("P001", WellKnownCategories.Protocol, "Protocol Violation");
        private static readonly Rule RuleGets = new Rule("P001", WellKnownCategories.Protocol, "Protocol Violation", new[] { "Apache" });

        public void Inspect(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            var method = context.Request.Method;

            if (!HttpMethods.IsGet(method) &&
                !HttpMethods.IsHead(method) &&
                !HttpMethods.IsOptions(method) &&
                !HttpMethods.IsPost(method) &&
                !HttpMethods.IsDelete(method) &&
                !HttpMethods.IsPut(method) &&
                !HttpMethods.IsPatch(method) &&
                !HttpMethods.IsConnect(method)
            )
            {
                // TRACE must be disabled
                if (HttpMethods.IsTrace(method))
                {
                    context.ReportDiagnostic(new Diagnostic(RuleTrace, Location.Method));
                    return;
                }

                // unknown method
                context.ReportDiagnostic(new Diagnostic(Rule, Location.Method));

                // Apache directory listing exploit
                if (method.Equals("GETS", StringComparison.OrdinalIgnoreCase))
                {
                    context.ReportDiagnostic(new Diagnostic(RuleGets, Location.Method));
                }
            }
        }
    }
}

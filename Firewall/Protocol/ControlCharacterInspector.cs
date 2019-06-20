using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Threading;

namespace Firewall
{
    public class ControlCharacterInspector : IRequestInspector
    {
        private static readonly Rule Rule = new Rule("1", "Other", "Control character found.");

        public void Inspect(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Request.Path.Value.Any(Char.IsControl))
            {
                context.ReportDiagnostic(new Diagnostic(Rule, Location.Path));
                return;
            }

            if (context.Request.QueryString.Value.Any(Char.IsControl))
            {
                context.ReportDiagnostic(new Diagnostic(Rule, Location.QueryString()));
                return;
            }

            foreach (var header in context.Request.Headers.Where(h => h.Key.Any(Char.IsControl) || h.Value.Any(v => v.Any(Char.IsControl))))
            {
                context.ReportDiagnostic(new Diagnostic(Rule, Location.RequestHeader(header.Key)));
                return;
            }
        }
    }
}

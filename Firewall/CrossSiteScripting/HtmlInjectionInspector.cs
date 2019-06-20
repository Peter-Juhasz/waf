using System;
using System.Threading;

namespace Firewall
{
    public class HtmlInjectionInspector : IResponseInspector
    {
        private static readonly Rule Rule = new Rule("I001", WellKnownCategories.Injection, "Cross-Site Scripting");

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                var html = context.ReadAsString();
                if (html == null)
                {
                    return;
                }

                foreach (var query in context.Response.HttpContext.Request.Query)
                {
                    foreach (var value in query.Value)
                    {
                        if (ShouldEncode(value))
                        {
                            if (html.Contains(value, StringComparison.Ordinal))
                            {
                                context.ReportDiagnostic(new Diagnostic(Rule, Location.QueryString(query.Key)));
                            }
                        }
                    }
                }
            }
        }

        private static readonly char[] Meta = new[] { '<', '>', '"', '\'', '&' };

        private static bool ShouldEncode(string str) => str.IndexOfAny(Meta) != -1;
    }
}

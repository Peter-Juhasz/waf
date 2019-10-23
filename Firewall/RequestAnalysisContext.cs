using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Firewall
{
    public class RequestAnalysisContext
    {
        public RequestAnalysisContext(HttpRequest request)
        {
            Request = request;
        }

        public HttpRequest Request { get; }

        public HttpContext HttpContext => Request.HttpContext;

        public bool IsMalicious => Diagnostics.Any();

        private ImmutableList<Diagnostic> diagnostics = ImmutableList<Diagnostic>.Empty;
        public IReadOnlyCollection<Diagnostic> Diagnostics => diagnostics;

        private RequestHeaders? typedHeaders;
        public RequestHeaders TypedHeaders
        {
            get
            {
                if (typedHeaders == null)
                {
                    typedHeaders = Request.GetTypedHeaders();
                }

                return typedHeaders;
            }
        }

        private IReadOnlyList<StringSegment>? tokenizedPath;
        private static readonly char[] PathSeparator = new[] { '/' };
        public IReadOnlyList<StringSegment> TokenizedPath
        {
            get
            {
                if (tokenizedPath == null)
                {
                    tokenizedPath = new StringTokenizer(Request.Path.Value, PathSeparator).ToList();
                }

                return tokenizedPath;
            }
        }

        public void ReportDiagnostic(Diagnostic diagnostic)
        {
            diagnostics = diagnostics.Add(diagnostic);
        }
    }
}

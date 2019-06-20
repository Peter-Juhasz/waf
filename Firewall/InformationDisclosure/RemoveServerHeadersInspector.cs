using Microsoft.AspNetCore.Http;
using System;
using System.Threading;

namespace Firewall
{
    internal sealed class RemoveServerHeadersInspector : IResponseInspector
    {
        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            var response = context.Response;

            if (response.Headers.ContainsKey("Server"))
            {
                response.Headers.Remove("Server");
            }

            if (response.Headers.ContainsKey("Via"))
            {
                response.Headers.Remove("Via");
            }

            if (response.Headers.ContainsKey("X-Generator"))
            {
                response.Headers.Remove("X-Generator");
            }

            if (response.Headers.ContainsKey("X-Powered-By"))
            {
                response.Headers.Remove("X-Powered-By");
            }
        }
    }
}

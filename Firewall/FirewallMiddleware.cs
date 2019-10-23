using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Firewall
{
    public class FirewallMiddleware : IMiddleware
    {
        public FirewallMiddleware(
            ObjectPool<MemoryStream> memoryStreamPool,
            IEnumerable<IRequestInspector> requestInspectors,
            IEnumerable<IAsyncRequestInspector> asyncRequestInspectors,
            IEnumerable<IResponseInspector> responseInspectors,
            IEnumerable<IAsyncResponseInspector> asyncResponseInspectors,
            IOptions<FirewallOptions> options,
            ILogger<FirewallMiddleware> logger
        )
        {
            MemoryStreamPool = memoryStreamPool;
            RequestInspectors = requestInspectors;
            AsyncRequestInspectors = asyncRequestInspectors;
            ResponseInspectors = responseInspectors;
            AsyncResponseInspectors = asyncResponseInspectors;
            Options = options;
            Logger = logger;
        }

        public ObjectPool<MemoryStream> MemoryStreamPool { get; }
        public IEnumerable<IRequestInspector> RequestInspectors { get; }
        public IEnumerable<IAsyncRequestInspector> AsyncRequestInspectors { get; }
        public IEnumerable<IResponseInspector> ResponseInspectors { get; }
        public IEnumerable<IAsyncResponseInspector> AsyncResponseInspectors { get; }
        public IOptions<FirewallOptions> Options { get; }
        public ILogger<FirewallMiddleware> Logger { get; }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            var options = Options.Value;
            context.Request.EnableBuffering();

            // analyze request
            var requestAnalysisContext = new RequestAnalysisContext(context.Request);

            AnalyzeRequest(requestAnalysisContext, context.RequestAborted);
            if (requestAnalysisContext.IsMalicious && options.Depth == AnalysisDepth.FindFirst)
            {
                await Handle(requestAnalysisContext.Diagnostics);
                return;
            }

            await AnalyzeRequestAsync(requestAnalysisContext, context.RequestAborted);
            if (requestAnalysisContext.IsMalicious && options.Depth == AnalysisDepth.FindFirst)
            {
                await Handle(requestAnalysisContext.Diagnostics);
                return;
            }

            // switch body to buffer
            var original = context.Response.Body;
            var buffer = MemoryStreamPool.Get();
            context.Response.Body = buffer;

            var responseAnalysisContext = new ResponseAnalysisContext(context.Response);

            try
            {
                // execute
                await next(context);

                // analyze response
                AnalyzeResponse(responseAnalysisContext, context.RequestAborted);
                if (responseAnalysisContext.IsMalicious && options.Depth == AnalysisDepth.FindFirst)
                {
                    await Handle(responseAnalysisContext.Diagnostics);
                    return;
                }

                await AnalyzeResponseAsync(responseAnalysisContext, context.RequestAborted);
                if (responseAnalysisContext.IsMalicious && options.Depth == AnalysisDepth.FindFirst)
                {
                    await Handle(responseAnalysisContext.Diagnostics);
                    return;
                }
            }
            finally
            {
                context.Response.Body = original;
            }

            // write response
            if (responseAnalysisContext.Version != 0)
            {
                // remove content-related headers, because may be outdated
                if (context.Response.Headers.ContainsKey("Content-Encoding"))
                {
                    context.Response.Headers.Remove("Content-Encoding");
                }

                if (context.Response.Headers.ContainsKey("Content-MD5"))
                {
                    context.Response.Headers.Remove("Content-MD5");
                }

                // based on body type
                switch (responseAnalysisContext.SnapshotBodyType)
                {
                    case ResponseBodyType.String:
                        {
                            var body = responseAnalysisContext.ReadAsString(applyPendingChanges: true);
                            byte[] buffer1 = Encoding.UTF8.GetBytes(body);
                            context.Response.ContentLength = buffer1.Length;
                            context.Response.Headers["Content-Length"] = buffer1.Length.ToString();
                            await context.Response.Body.WriteAsync(buffer1, 0, buffer1.Length);
                        }
                        break;

                    case ResponseBodyType.Stream:
                        {
                            var body = responseAnalysisContext.ReadAsStream();
                            context.Response.ContentLength = body.Length;
                            context.Response.Headers["Content-Length"] = body.Length.ToString();
                            await body.CopyToAsync(context.Response.Body);
                        }
                        break;

                    case ResponseBodyType.ByteArray:
                        {
                            var body = responseAnalysisContext.ReadAsByteArray();
                            context.Response.ContentLength = body.Length;
                            context.Response.Headers["Content-Length"] = body.Length.ToString();
                            await context.Response.Body.WriteAsync(body, 0, body.Length);
                        }
                        break;
                }
            }
            else
            {
                // write original response
                if (buffer.Length > 0)
                {
                    await buffer.Rewind().CopyToAsync(context.Response.Body);
                }
            }


            async Task Handle(IReadOnlyCollection<Diagnostic> diagnostics)
            {
                if (diagnostics.Count == 1)
                {
                    var diagnostic = diagnostics.Single();
                    Logger.LogWarning($"Request denied. {diagnostic.Rule.Category} ({diagnostic.Rule.Id}) attack found in {diagnostic.Location}: {diagnostic.Rule.Description}.");
                }
                else
                {
                    Logger.LogWarning($"Request denied. Found {diagnostics.Count} diagnostics.");
                }

                if (options.Mode == FirewallMode.Prevention)
                {
                    context.Response.StatusCode = options.DeniedResponseStatusCode;
                }

                var settings = new JsonSerializerOptions();
                settings.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                settings.WriteIndented = true;
                var dto = new { diagnostics };
                var json = JsonSerializer.Serialize(dto, settings);
                context.Response.ContentLength = Encoding.UTF8.GetByteCount(json);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(json);
            }
        }


        protected void AnalyzeRequest(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            foreach (var inspector in RequestInspectors)
            {
                inspector.Inspect(context, cancellationToken);
                if (context.IsMalicious && Options.Value.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }
        }

        protected async Task AnalyzeRequestAsync(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            foreach (var inspector in AsyncRequestInspectors)
            {
                await inspector.InspectAsync(context, cancellationToken);
                if (context.IsMalicious && Options.Value.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }
        }

        protected void AnalyzeResponse(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            foreach (var inspector in ResponseInspectors)
            {
                inspector.Inspect(context, cancellationToken);
                if (context.IsMalicious && Options.Value.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }
        }

        protected async Task AnalyzeResponseAsync(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            foreach (var inspector in AsyncResponseInspectors)
            {
                await inspector.InspectAsync(context, cancellationToken);
                if (context.IsMalicious && Options.Value.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }
        }
    }
}

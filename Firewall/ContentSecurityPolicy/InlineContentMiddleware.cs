using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Firewall.ContentSecurityPolicy
{
    internal class InlineContentMiddleware : IMiddleware
    {
        public InlineContentMiddleware(InlineContentService inlineContentService)
        {
            InlineContentService = inlineContentService;
        }

        public InlineContentService InlineContentService { get; }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            if (context.Request.Path.StartsWithSegments("/.waf/styles", out var stylesHash))
            {
                var hash = stylesHash.Value.Substring(1);
                if (InlineContentService.TryGetStyleByHash(hash, out var content))
                {
                    context.Response.Headers.Add("Cache-Control", "public, immutable");
                    await context.Response.SetBodyFromStringAsync(content, "text/css");
                }
                else
                {
                    context.Response.StatusCode = 404;
                    context.Response.Headers.Add("Cache-Control", "no-cache");
                }
            }

            else if (context.Request.Path.StartsWithSegments("/.waf/scripts", out var scriptHash))
            {
                var hash = scriptHash.Value.Substring(1);
                if (InlineContentService.TryGetScriptByHash(hash, out var content))
                {
                    context.Response.Headers.Add("Cache-Control", "public, immutable");
                    await context.Response.SetBodyFromStringAsync(content, "text/javascript");
                }
                else
                {
                    context.Response.StatusCode = 404;
                    context.Response.Headers.Add("Cache-Control", "no-cache");
                }
            }

            else
            {
                await next(context);
            }
        }
    }
}

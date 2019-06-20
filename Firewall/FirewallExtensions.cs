using Firewall;
using Firewall.ContentSecurityPolicy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.ObjectPool;
using System.IO;
using System.Text;

namespace Microsoft.AspNetCore.Builder
{
    public static class FirewallExtensions
    {
        public static IServiceCollection AddWebApplicationFirewall(this IServiceCollection services)
        {
            services.AddSingleton<InlineContentMiddleware>();

            services.AddSingleton<FirewallMiddleware>()
                .AddAntiforgery()
                .AddMemoryCache()
                .AddHttpClient()
                .AddSingleton<ObjectPool<StringBuilder>>(new DefaultObjectPool<StringBuilder>(new StringBuilderPooledObjectPolicy()))
                .AddSingleton<ObjectPool<MemoryStream>>(new DefaultObjectPool<MemoryStream>(new MemoryStreamPoolPolicy()))
                .AddSingleton<InlineContentService>()
                .AddSingleton<IRequestInspector, ProtocolEnforcementInspector>()
                .AddSingleton<IRequestInspector, BlacklistInspector>()
                .AddSingleton<IRequestInspector, ControlCharacterInspector>()
                .AddSingleton<IRequestInspector, ScannerInspector>()
                .AddSingleton<IAsyncRequestInspector, AntiforgeryResponseInspector>()
                .AddSingleton<IResponseInspector, DecompressionInspector>()
                .AddSingleton<IResponseInspector, BlacklistInspector>()
                .AddSingleton<IResponseInspector, HtmlInjectionInspector>()
                .AddSingleton<IResponseInspector, RewriteHttpsInspector>()
                .AddSingleton<IResponseInspector, RemoveServerHeadersInspector>()
                .AddSingleton<IResponseInspector, RemoveGeneratorInspector>()
                .AddSingleton<IResponseInspector, UpgradeCookieResponseInspector>()
                .AddSingleton<IResponseInspector, AntiforgeryResponseInspector>()
                .AddSingleton<IResponseInspector, SessionHijackInspector>()
                .AddSingleton<IResponseInspector, InlineRewriterInspector>()
                .AddSingleton<IResponseInspector, RemoveCommentsInspector>()
                .AddSingleton<IAsyncResponseInspector, SubResourceIntegrityInspector>()
            ;

            return services;
        }

        public static IApplicationBuilder UseWebApplicationFirewall(this IApplicationBuilder app)
        {
            app.UseMiddleware<InlineContentMiddleware>();
            app.UseMiddleware<FirewallMiddleware>();
            return app;
        }
    }
}

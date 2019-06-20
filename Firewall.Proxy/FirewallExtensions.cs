using Firewall;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder
{
    public static class FirewallExtensions
    {
        public static IServiceCollection AddProxy(this IServiceCollection services)
        {
            services.AddSingleton<ProxyMiddleware>().AddHttpClient<ProxyMiddleware>();
            return services;
        }

        public static IApplicationBuilder UseProxy(this IApplicationBuilder app) => app.UseMiddleware<ProxyMiddleware>();
    }
}

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Firewall.Tests
{
    public class TestWebApplicationFactory : WebApplicationFactory<Startup>
    {
        public TestWebApplicationFactory()
            : base()
        {

        }

        public TestWebApplicationFactory(RequestDelegate requestDelegate)
            : this()
        {
            RequestDelegate = requestDelegate;
        }

        public RequestDelegate? RequestDelegate { get; }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            if (RequestDelegate != null)
            {
                builder.ConfigureServices((IServiceCollection services) => services.AddSingleton<RequestDelegate>(RequestDelegate));
            }

            base.ConfigureWebHost(builder);
        }

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return WebHost.CreateDefaultBuilder().UseStartup<Startup>();
        }
    }
}
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Firewall.Tests
{
    public class FirewallStartup
    {
        public IConfiguration Configuration { get; }

        public FirewallStartup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<FirewallOptions>(Configuration.GetSection("Firewall"));
            services.AddWebApplicationFirewall();
            services.AddHttpClient();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IServiceProvider serviceProvider)
        {
            app.UseWebApplicationFirewall();

            var rd = serviceProvider.GetService<RequestDelegate>();
            if (rd != null)
            {
                app.Run(rd);
            }
        }
    }
}

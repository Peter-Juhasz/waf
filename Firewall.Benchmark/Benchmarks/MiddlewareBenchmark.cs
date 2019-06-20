using BenchmarkDotNet.Attributes;
using Firewall.Tests;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firewall.Benchmark
{
    [InProcess]
    public class MiddlewareBenchmark
    {
        [GlobalSetup]
        public void Setup()
        {
            var factory = new TestWebApplicationFactory<FirewallStartup>(async context =>
            {
                await context.Response.SetBodyFromStringAsync("Hello world!");
            });
            client = factory.CreateDefaultClient();

            var simpleFactory = new TestWebApplicationFactory<SimpleStartup>(async context =>
            {
                await context.Response.SetBodyFromStringAsync("Hello world!");
            });
            simpleClient = simpleFactory.CreateDefaultClient();
        }

        HttpClient client;
        HttpClient simpleClient;

        [Benchmark]
        public async Task FirewallGet()
        {
            using var response = await client.GetAsync("/");
        }

        [Benchmark]
        public async Task SimpleGet()
        {
            using var response = await simpleClient.GetAsync("/");
        }
    }
}

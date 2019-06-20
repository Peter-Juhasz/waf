using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class CrossSiteScriptingTests
    {
        [TestMethod]
        public async Task InjectSimpleFromParameter_ShouldAccept()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                var p = context.Request.Query["p"];
                await context.Response.SetBodyFromStringAsync($"<div>{p}</div>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/?p=asd");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public async Task InjectXssFromParameter_ShouldBlock()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                var p = context.Request.Query["p"];
                await context.Response.SetBodyFromStringAsync($"<div>{p}</div>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/?p=<script>");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task InjectXssFromParameterEncoded_ShouldAccept()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                var p = context.Request.Query["p"];
                await context.Response.SetBodyFromStringAsync($"<div>{HtmlEncoder.Default.Encode(p)}</div>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/?p=<script>");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }
    }
}

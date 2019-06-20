using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class SessionHijackTests
    {
        [TestMethod]
        public async Task InjectSimpleFromParameter_ShouldAccept()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                context.Response.StatusCode = 204;
                context.Response.Cookies.Append("Session", "ZP1hBzeiqjdPFiPRf2JH");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/?p=asd");

            Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
        }

        [TestMethod]
        public async Task InjectXssFromParameter_ShouldBlock()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                var p = context.Request.Query["p"];
                context.Response.Cookies.Append("Session", p);
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/?p=ZP1hBzeiqjdPFiPRf2JH");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }
    }
}

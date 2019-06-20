using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class HelloWorldTests
    {
        [TestMethod]
        public async Task HttpMethodGETS()
        {
            var reference = "Hello world!";
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync(reference);
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(reference, await response.Content.ReadAsStringAsync());
        }
    }
}

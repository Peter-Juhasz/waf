using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class ProtocolTests
    {
        [TestMethod]
        public async Task HttpMethodTRACE()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var message = new HttpRequestMessage(new HttpMethod("TRACE"), "/");
            using var response = await http.SendAsync(message);

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task HttpMethodGETS()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var message = new HttpRequestMessage(new HttpMethod("GETS"), "/");
            using var response = await http.SendAsync(message);

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }
    }
}

using System.Threading;
using System.Threading.Tasks;

namespace Firewall
{
    public interface IAsyncRequestInspector
    {
        Task InspectAsync(RequestAnalysisContext context, CancellationToken cancellationToken);
    }
}

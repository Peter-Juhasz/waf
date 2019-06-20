using System.Threading;
using System.Threading.Tasks;

namespace Firewall
{
    public interface IAsyncResponseInspector
    {
        Task InspectAsync(ResponseAnalysisContext context, CancellationToken cancellationToken);
    }
}

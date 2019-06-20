using Microsoft.Extensions.ObjectPool;
using System.IO;

namespace Firewall
{
    public class MemoryStreamPoolPolicy : IPooledObjectPolicy<MemoryStream>
    {
        public MemoryStream Create()
        {
            return new MemoryStream(capacity: 4096);
        }

        public bool Return(MemoryStream obj)
        {
            if (obj.Capacity > 65536)
            {
                obj.Dispose();
                return false;
            }

            obj.SetLength(0);
            return true;
        }
    }
}

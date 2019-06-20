using System.Collections.Concurrent;

namespace Firewall.ContentSecurityPolicy
{
    public class InlineContentService
    {
        private readonly ConcurrentDictionary<string, string> Styles = new ConcurrentDictionary<string, string>();
        private readonly ConcurrentDictionary<string, string> Scripts = new ConcurrentDictionary<string, string>();

        public bool ContainsStyleByHash(string hash) => Styles.ContainsKey(hash);
        public bool ContainsScriptByHash(string hash) => Scripts.ContainsKey(hash);

        public void TryAddStyleByHash(string hash, string content)
        {
            Styles.TryAdd(hash, content);
        }

        public bool TryGetStyleByHash(string hash, out string? content)
        {
            return Styles.TryGetValue(hash, out content);
        }

        public void TryAddScriptByHash(string hash, string content)
        {
            Scripts.TryAdd(hash, content);
        }

        public bool TryGetScriptByHash(string hash, out string? content)
        {
            return Scripts.TryGetValue(hash, out content);
        }

    }
}

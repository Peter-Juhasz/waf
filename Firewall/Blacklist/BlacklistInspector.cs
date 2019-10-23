using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;

namespace Firewall
{
    public class BlacklistInspector : IRequestInspector, IResponseInspector, IDisposable
    {
        public BlacklistInspector(IOptionsMonitor<FirewallOptions> options)
        {
            AllRules = Directory.GetFiles(".", "ruleset.*.json", SearchOption.AllDirectories)
                .Select(path => JsonSerializer.Deserialize<RuleFile>(File.ReadAllText(path)))
                .SelectMany(f => f.Rules)
                .OrderBy(l => l.Term)
                .ToList();

            Options = options;
            FilterRules(options.CurrentValue);
            _optionsMonitor = options.OnChange(FilterRules);
        }

        private readonly IDisposable _optionsMonitor;

        private void FilterRules(FirewallOptions options)
        {
            var filteredRules = AllRules.Where(r => FilterByTags(options, r));

            RequestBody = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.RequestBody))
                .ToList();

            ResponseBody = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.ResponseBody))
                .ToList();

            Files = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.PathFileName))
                .ToList();

            Folders = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.PathSegment))
                .ToList();

            Extensions = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.PathFileNameExtension))
                .ToList();

            UserAgents = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.RequestHeaderUserAgent))
                .ToList();

            FormFileName = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.RequestFormFileName))
                .ToList();

            FormFileNameExtension = filteredRules
                .Where(r => r.Locations.Contains(LocationKind.RequestFormFileNameExtension))
                .ToList();
        }

        private static bool FilterByTags(FirewallOptions options, ListRule r)
        {
            if (r.Tags == null)
            {
                return true;
            }

            if (options.IncludedTags != null)
            {
                if (r.Tags.Any(options.IncludedTags.Contains))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }

            if (options.ExcludedTags != null)
            {
                if (r.Tags.Any(options.ExcludedTags.Contains))
                {
                    return false;
                }
            }

            return true;
        }

        public IReadOnlyCollection<ListRule> AllRules { get; private set; }

        private IReadOnlyCollection<ListRule> RequestBody;
        private IReadOnlyCollection<ListRule> ResponseBody;
        private IReadOnlyCollection<ListRule> Files;
        private IReadOnlyCollection<ListRule> Folders;
        private IReadOnlyCollection<ListRule> Extensions;
        private IReadOnlyCollection<ListRule> UserAgents;
        private IReadOnlyCollection<ListRule> FormFileName;
        private IReadOnlyCollection<ListRule> FormFileNameExtension;

        private static readonly Rule Rule = new Rule("1", WellKnownCategories.InformationDisclosure, "Information leakage.");

        public IOptionsMonitor<FirewallOptions> Options { get; }

        public void Inspect(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            var options = Options.CurrentValue;

            // inspect file extension
            var file = context.TokenizedPath.LastOrDefault();
            if (file != null && file.Contains('.'))
            {
                foreach (var found in Extensions.Where(e => file.EndsWith(e.Term, StringComparison.OrdinalIgnoreCase)))
                {
                    context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.Path));

                    if (options.Depth == AnalysisDepth.FindFirst)
                    {
                        return;
                    }
                }
            }

            // inspect directories
            foreach (var found in Folders.Where(s => context.TokenizedPath.Any(d => d.Equals(s.Term, StringComparison.OrdinalIgnoreCase))))
            {
                context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.Path));

                if (options.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }

            // inspect file name
            if (file != null)
            {
                foreach (var found in Files.Where(e => file.Equals(e.Term, StringComparison.OrdinalIgnoreCase)))
                {
                    context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.Path));

                    if (options.Depth == AnalysisDepth.FindFirst)
                    {
                        return;
                    }
                }
            }

            // inspect path
            var path = context.Request.Path.Value;
            foreach (var found in RequestBody.Where(i => path.Contains(i.Term, StringComparison.OrdinalIgnoreCase)))
            {
                context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.Path));

                if (options.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }

            // inspect query string
            var queryString = context.Request.QueryString.Value;
            if (!String.IsNullOrEmpty(queryString))
            {
                foreach (var found in RequestBody.Where(i => queryString.Contains(i.Term, StringComparison.OrdinalIgnoreCase)))
                {
                    context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.QueryString()));

                    if (options.Depth == AnalysisDepth.FindFirst)
                    {
                        return;
                    }
                }
            }

            // inspect headers
            foreach (var header in context.Request.Headers)
            foreach (var value in header.Value)
            foreach (var found in RequestBody.Where(i => value.Contains(i.Term, StringComparison.OrdinalIgnoreCase)))
            {
                context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.RequestHeader(header.Key)));

                if (options.Depth == AnalysisDepth.FindFirst)
                {
                    return;
                }
            }

            // inspect user agent
            if (context.Request.Headers.TryGetValue("User-Agent", out var userAgent))
            {
                foreach (var ua in userAgent)
                foreach (var found in UserAgents.Where(u => ua.Contains(u.Term, StringComparison.OrdinalIgnoreCase)))
                {
                    context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.RequestHeader("User-Agent")));

                    if (options.Depth == AnalysisDepth.FindFirst)
                    {
                        return;
                    }
                }
            }

            // inspect headers
            if (context.Request.HasFormContentType && context.Request.Form != null)
            {
                // inspect files
                foreach (var formFile in context.Request.Form.Files)
                {
                    var fileName = Path.GetFileName(formFile.FileName);

                    // inspect file extension
                    foreach (var found in FormFileNameExtension.Where(i => fileName.EndsWith(i.Term, StringComparison.OrdinalIgnoreCase)))
                    {
                        context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.RequestFormFile(formFile.FileName)));

                        if (options.Depth == AnalysisDepth.FindFirst)
                        {
                            return;
                        }
                    }

                    // inspect file name
                    foreach (var found in FormFileName.Where(i => fileName.Equals(i.Term, StringComparison.OrdinalIgnoreCase)))
                    {
                        context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.RequestFormFile(formFile.FileName)));

                        if (options.Depth == AnalysisDepth.FindFirst)
                        {
                            return;
                        }
                    }
                }
            }
        }

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsTextLike())
            {
                var content = context.ReadAsString();
                foreach (var found in ResponseBody.Where(b => content.Contains(b.Term)))
                {
                    context.ReportDiagnostic(new Diagnostic(Rule.With(found), Location.ResponseBody));

                    if (Options.CurrentValue.Depth == AnalysisDepth.FindFirst)
                    {
                        return;
                    }
                }
            }
        }


        public void Dispose()
        {
            _optionsMonitor.Dispose();
        }
    }
}

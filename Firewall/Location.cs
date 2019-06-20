namespace Firewall
{
    public class Location
    {
        private Location(LocationKind diagnosticLocation)
        {
            ContextPart = diagnosticLocation;
        }
        private Location(LocationKind diagnosticLocation, string name)
        {
            ContextPart = diagnosticLocation;
            Name = name;
        }

        public LocationKind ContextPart { get; }
        public string? Name { get; }


        public static readonly Location Path = new Location(LocationKind.Path);
        public static readonly Location Method = new Location(LocationKind.Method);
        public static readonly Location RequestBody = new Location(LocationKind.RequestBody);
        public static readonly Location ResponseBody = new Location(LocationKind.ResponseBody);

        public static Location QueryString() => new Location(LocationKind.Query);
        public static Location QueryString(string name) => new Location(LocationKind.QueryValue, name);
        public static Location RequestHeader(string name) => new Location(LocationKind.RequestHeaderValue, name);
        public static Location ResponseHeader(string name) => new Location(LocationKind.ResponseHeaderValue, name);

        public static Location RequestFormFile(string name) => new Location(LocationKind.RequestFormFieldName, name);

    }
}

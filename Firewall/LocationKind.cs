namespace Firewall
{
    public enum LocationKind
    {
        Method,

        Path,
        PathSegment,
        PathFileName,
        PathFileNameExtension,

        Query,
        QueryName,
        QueryValue,

        RequestHeader,
        RequestHeaderName,
        RequestHeaderValue,
        RequestHeaderUserAgent,

        RequestFormFieldName,
        RequestFormFieldValue,
        RequestFormFileBody,
        RequestFormFileName,
        RequestFormFileNameExtension,

        RequestBody,

        ResponseHeader,
        ResponseHeaderName,
        ResponseHeaderValue,

        ResponseBody,
    }
}

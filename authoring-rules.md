# Authoring Rules

## Analyzing requests

For analyzing requests you have to implement the `IRequestInspector` (or `IAsyncRequestInspector`) interface:

```csharp
public class DisallowSecretFolderRule : IRequestInspector
{
    private static readonly Rule Rule = new Rule(
        id: "CR001",
        category: WellKnownCategories.InformationDisclosure,
        tags: new [] { "Internal" }
    );

    public void Inspect(RequestAnalysisContext context)
    {
        if (context.Request.Path.StartsWith("/secret"))
        {
            context.ReportDiagnostic(new Diagnostic(Rule, Location.Path));
        }
    }
}
```

Add your rule to the DI container:

```csharp
services.AddSingleton<IRequestInspector, DisallowSecretFolderRule>();
```

## Analyzing responses



### Reading and modifying response bodies

Response bodies are always buffered up to `4 MB`, so they can be read synchronously.

The response body can be read in different formats:
 - `ReadAsStream` reads it as a `Stream`
 - `ReadAsString` reads it as a `String`

But it also means that the response body has to be converted into another format in memory, so the response body may appear multiple times in memory.



## Performance guidelines
 - Do not use regular expressions, because they are slow
 - Avoid reading response body as string if not necessary
 - Use new .NET primitives like `StringSegment` wherever possible
 - Do not manipulate response body directly, create atomic `TextChange`s and use `AddChange` API instead
 - Use `FastHtmlParser` to do simple HTML operations
 - On `RequestAnalysisContext` you can use:
	- `TokenizedPath` to get a parsed collection of segments of the `Path`.
	- `TypedHeaders` to get a parsed collection of headers.
 - On `ResponseAnalysisContext` you can use:
	- `TokenizedPath` to get a parsed collection of segments of the `Path`.
	- `TypedHeaders` to get a parsed collection of headers.
 - Register your inspectors with Singleton lifetime.

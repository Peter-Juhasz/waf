# Next Generation Web Application Firewall

## Features
 - Can be hosted in-app
 - Blazing-fast, as it is built on top of new .NET Core primitives
 - Extensibility, easy to author new rules
 - Easy deployment to the cloud, to the edge, or even on-premise
 - Application Insights integration

## Protection
 - Protocol validation
 - Information disclosure
 - Cross-Site Scripting (XSS, Reflected)
 - Popular scanners & bots
 - Blacklist
 - Augment: Rewrite references to HTTPS
 - Augment: Antiforgery (CSRF)
 - Augment: Sub-Resource Integrity

## For developers

### Hosting in-app
You can easily add the WAF middleware to the HTTP pipeline:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddWebApplicationFirewall(); // setup
}

public void Configure(IApplicationBuilder app)
{
    app.UseWebApplicationFirewall(); // add middleware

    // add any other application logic behind it
    app.UseStaticFiles();
    app.UseMvc();
}
```

### Authoring rules
You can implement rules by implementing the `IRequestInspector` or `IResponseInspector` interfaces.

```csharp
public void Inspect(RequestAnalysisContext context)
{
    if (context.Request.Path.StartsWith("/secret"))
    {
        context.ReportDiagnostic(new Diagnostic(Rule, Location.Path));
    }
}
```

View [Authoring Rules](authoring-rules) for full documentation.

### Building a reverse-proxy
You can host it as a standalone reverse proxy as well, by proxying all requests after the WAF has inspected them. You can configure the rules by adding individual packages.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddWebApplicationFirewall()
        .AddDrupal() // add rule set
        .AddWordPress() // add rule set
    ;
}

public void Configure(IApplicationBuilder app)
{
    app.UseWebApplicationFirewall();

    app.UseProxy();
}
```


## For network administrators

Requirements:
 - .NET Core 3.0 Runtime
 - Windows or Linux that is supported by .NET Core

### Configuration
Configuration of the Firewall is under the `Firewall` configuration section.
 - `Mode`
   - `Detection` only detects potential attacks.
   - `Prevention` (default) not only detects, but prevents potential attacks.
 - `DeniedResponseStatusCode` (default: `403`) status code to set on a denied request.
 - `Depth`
   - `FindFirst` (default) stops analysis after detecting the first positive result.
   - `FindAll` collects all findings about a given request-response pair.
 - `IncludedTags` white list rules based on tags. No other rules are evaluated.
 - `ExcludedTags` black list rules based on tags. All other rules are evaluated.

Configuration of the reverse proxy middleware is under the `Proxy` configuration section.
 - `Scheme` request scheme to use (default: `https`)
 - `Host` hostname to send as origin
 - `Port` destination port (default: 443)

### Deploy to the cloud
Create a Web App in Azure and deploy the code.

### Deploy using Docker




## Limitations
 - Web sockets are not supported yet.
 - Serving large files as we have to inspect them may consume resources.

## Notes
 - The middleware buffers requests and responses, so it can inspect them.

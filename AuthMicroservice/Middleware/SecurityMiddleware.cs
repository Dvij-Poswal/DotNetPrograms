using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;

namespace AuthMicroservice.Middleware;

public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly ConcurrentDictionary<string, List<DateTime>> _requests = new();
    private static readonly object _lock = new();

    public RateLimitingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var key = GetClientKey(context);
        var now = DateTime.UtcNow;
        var limit = GetRateLimit(context.Request.Path.ToString());

        List<DateTime> timestamps;
        lock (_lock)
        {
            timestamps = _requests.GetOrAdd(key, _ => new List<DateTime>());
            timestamps.RemoveAll(time => time < now.AddMinutes(-15));
            timestamps.Add(now);
        }

        var requestCount = timestamps.Count;

        if (requestCount > limit)
        {
            context.Response.StatusCode = 429;
            await context.Response.WriteAsync(JsonSerializer.Serialize(new { Message = "Too many requests" }));
            return;
        }

        await _next(context);
    }

    private string GetClientKey(HttpContext context)
    {
        var userId = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return userId ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private int GetRateLimit(string path)
    {
        if (string.IsNullOrEmpty(path))
            return 100;

        var lowerPath = path.ToLowerInvariant();
        if (lowerPath.Contains("/login")) return 5;
        if (lowerPath.Contains("/register")) return 3;
        if (lowerPath.Contains("/forgot-password")) return 3;
        return 100;
    }
}

public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.TryAdd("X-Frame-Options", "DENY");
        context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
        context.Response.Headers.TryAdd("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.TryAdd("Referrer-Policy", "strict-origin-when-cross-origin");
        
        await _next(context);
    }
}

public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var startTime = DateTime.UtcNow;
        var requestId = Guid.NewGuid().ToString()[..8];

        _logger.LogInformation("Request {RequestId}: {Method} {Path}", 
            requestId, context.Request.Method, context.Request.Path);

        await _next(context);

        var duration = DateTime.UtcNow - startTime;
        _logger.LogInformation("Response {RequestId}: {StatusCode} in {Duration}ms", 
            requestId, context.Response.StatusCode, duration.TotalMilliseconds);
    }
}

// Extension methods for middleware
public static class MiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimiting(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitingMiddleware>();
    }

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SecurityHeadersMiddleware>();
    }

    public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RequestLoggingMiddleware>();
    }
}
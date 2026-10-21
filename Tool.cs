using System.Net;
using System.Text.Json.Nodes;
namespace WinDiagnostics;
public static class Tool
{
    public const string Name = "win-port-doctor";
    public static readonly string[] ValueOptions = ["--port"];
    public static readonly string[] Flags = [];
    public const string Help = "win-port-doctor --port 8080 [--json]\nShows TCP connections/listeners, UDP bindings, owner processes, and related services. Does not evaluate firewall reachability.";
    public static void ValidateOptions(Options o) { if (!o.Has("--port")) throw new ArgumentException("--port is required."); o.Number("--port", 0, 1, 65535); }
    public static Task<Collection> Collect(Options o, CancellationToken ct) => PowerShell.Collect(new() { ["WD_PORT"] = o.Get("--port") }, ct);
    public static void ValidateEvidence(JsonObject e) { J.Require(e,"port","listeners"); J.RequireRows(e,"listeners"); if (J.Number(e,"port") < 1 || J.Number(e,"port") > 65535) throw new ArgumentException("Evidence port must be 1–65535."); }
    public static List<Finding> Analyze(JsonObject e)
    {
        var result = new List<Finding>();
        var listeners = J.Rows(e,"listeners").Where(n => J.Text(n,"protocol")=="UDP" || J.Text(n,"state").Equals("Listen",StringComparison.OrdinalIgnoreCase)).ToArray();
        if (listeners.Length==0) result.Add(new("no-listener","warning","No TCP listener or UDP binding was observed",$"No server binding was recorded for local port {J.Text(e,"port")}. Existing TCP connections alone do not establish a listener.","Verify the intended server is running, its configured port, and any collection issues."));
        foreach(var row in listeners)
        {
            var address=J.Text(row,"address");
            if (IPAddress.TryParse(address,out var ip) && IPAddress.IsLoopback(ip)) result.Add(new("loopback-binding","warning","A binding is limited to loopback",$"{J.Text(row,"protocol")} {address}:{J.Text(e,"port")} belongs to PID {J.Text(row,"pid")}. Other computers cannot connect directly to this binding.","If remote access is intended, review the application's bind address and network policy."));
            else if(address is "0.0.0.0" or "::") result.Add(new("wildcard-binding","info","A wildcard binding was observed",$"{address} binds all local addresses in its address family. An IPv6 wildcard alone does not establish IPv4 support.","Check the client address family, routing, and firewall separately."));
        }
        if(J.Bool(e,"truncated")) result.Add(new("results-truncated","warning","Endpoint list was capped","Only the first 500 endpoints were retained.","Narrow the investigation with native network tools if the port has unusually many endpoints."));
        return result;
    }
    public static IEnumerable<string> Describe(JsonObject e)
    {
        yield return $"Local port: {J.Text(e,"port")}";
        foreach(var r in J.Rows(e,"listeners")) yield return $"{J.Text(r,"protocol"),-3} {J.Text(r,"address")}:{J.Text(e,"port")} {J.Text(r,"state")} | PID {J.Text(r,"pid")} | {J.Text(r["process"],"name","owner unavailable")} | services: {string.Join(", ",J.Strings(r,"services"))}";
    }
    public static string[] SmokeArgs => ["--port","1"];
}

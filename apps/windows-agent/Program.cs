using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Events;
using Vajra.WindowsAgent.Hosting;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;
using Vajra.WindowsAgent.Workers;

// VAJRA Windows Agent — interactive console or Windows Service
// Service name when installed: VajraGuardService

var argsList = args.ToList();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<AgentOptions>(
    builder.Configuration.GetSection(AgentOptions.SectionName));

var agentOptions = new AgentOptions();
builder.Configuration.GetSection(AgentOptions.SectionName).Bind(agentOptions);
// Environment overrides
if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("VAJRA_SERVER_BASE_URL")))
    agentOptions.ServerBaseUrl = Environment.GetEnvironmentVariable("VAJRA_SERVER_BASE_URL")!;
if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("VAJRA_DATA_DIRECTORY")))
    agentOptions.DataDirectory = Environment.GetEnvironmentVariable("VAJRA_DATA_DIRECTORY")!;

builder.Services.AddSingleton(agentOptions);
builder.Services.AddSingleton<DeviceIdentityStore>();
builder.Services.AddSingleton<WindowsEventCollector>();
builder.Services.AddHttpClient<VajraApiClient>();

builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<CommandPollerWorker>();
builder.Services.AddHostedService<EventUploadWorker>();

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o =>
{
    o.SingleLine = true;
    o.TimestampFormat = "HH:mm:ss ";
});

// Windows Service integration when running under SCM
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "VajraGuardService";
});

// Enrollment subcommand runs once and exits (no long-running host)
if (argsList.Count > 0 && (
    argsList[0].Equals("enroll", StringComparison.OrdinalIgnoreCase) ||
    argsList[0].Equals("--enroll", StringComparison.OrdinalIgnoreCase)))
{
    using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole());
    var logger = loggerFactory.CreateLogger("Enrollment");
    var store = new DeviceIdentityStore(agentOptions, loggerFactory.CreateLogger<DeviceIdentityStore>());
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(agentOptions.HttpTimeoutSeconds) };
    var api = new VajraApiClient(http, agentOptions, store, loggerFactory.CreateLogger<VajraApiClient>());
    return await EnrollmentCli.RunAsync(agentOptions, store, api, logger, argsList.Skip(1).ToArray(), CancellationToken.None);
}

if (argsList.Count > 0 && (
    argsList[0].Equals("status", StringComparison.OrdinalIgnoreCase) ||
    argsList[0].Equals("--status", StringComparison.OrdinalIgnoreCase)))
{
    using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole());
    var store = new DeviceIdentityStore(agentOptions, loggerFactory.CreateLogger<DeviceIdentityStore>());
    var id = store.LoadIdentity();
    if (id is null)
    {
        Console.WriteLine("Status: NOT_ENROLLED");
        return 0;
    }
    Console.WriteLine($"DeviceId: {id.DeviceId}");
    Console.WriteLine($"Fingerprint: {id.PublicKeyFingerprint}");
    Console.WriteLine($"LifecycleState (local): {id.LifecycleState}");
    Console.WriteLine($"Server: {id.ServerBaseUrl}");
    Console.WriteLine("Note: Local lifecycle may lag server until heartbeat succeeds after console confirmation.");
    return 0;
}

var host = builder.Build();
await host.RunAsync();
return 0;

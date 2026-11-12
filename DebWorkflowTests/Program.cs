using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using TrollDock.Services;

var bash = @"C:\Program Files\Git\bin\bash.exe";
var testRoot = Path.Combine(AppContext.BaseDirectory, "fixtures");
Directory.CreateDirectory(testRoot);
var unixRoot = "/" + testRoot[0].ToString().ToLowerInvariant() + testRoot[2..].Replace('\\', '/');
var rootless = unixRoot + "/jb";
var bin = Path.Combine(testRoot, "jb", "usr", "bin");
Directory.CreateDirectory(bin);
File.WriteAllText(Path.Combine(bin, "dpkg"), "#!/bin/sh\nprintf '%s\\n' \"${TD_DEVICE_ARCH:-iphoneos-arm64}\"\n");
File.WriteAllText(Path.Combine(bin, "dpkg-query"), """
    #!/bin/sh
    if [ "$4" = com.example.second ]; then
        case "$3" in
            '${Status}') printf '%s' "${TD_SECOND_STATUS:-install ok installed}" ;;
            '${Version}') printf '%s' "${TD_SECOND_INSTALLED_VERSION:-2.0}" ;;
            *) exit 2 ;;
        esac
        exit 0
    fi
    case "$3" in
        '${Status}') printf '%s' "${TD_STATUS:-install ok installed}" ;;
        '${Version}') printf '%s' "${TD_VERSION:-1.2.3-4}" ;;
        *) exit 2 ;;
    esac
    """ + "\n");
File.WriteAllText(Path.Combine(bin, "dpkg-deb"), """
    #!/bin/sh
    [ "$1" = -f ] || exit 2
    if [ "$2" = "${TD_SECOND_PATH:-}" ]; then
        case "$3" in
            Package) printf '%s\n' "${TD_SECOND_PACKAGE:-com.example.second}" ;;
            Version) printf '%s\n' '2.0' ;;
            Architecture) printf '%s\n' "${TD_SECOND_ARCH:-iphoneos-arm64}" ;;
            *) exit 2 ;;
        esac
        exit 0
    fi
    case "$3" in
        Package) printf '%s\n' "${TD_PACKAGE:-com.example.tweak}" ;;
        Version) printf '%s\n' '1.2.3-4' ;;
        Architecture) printf '%s\n' "${TD_ARCH:-iphoneos-arm64}" ;;
        *) exit 2 ;;
    esac
    """ + "\n");
File.WriteAllText(Path.Combine(bin, "apt-get"), """
    #!/bin/sh
    if [ "$1" = --simulate ]; then
        printf '%s\n' "$@" > "$TD_SIM_LOG"
        if [ "${TD_REQUIRE_PAIR:-0}" = 1 ]; then
            FIRST_FOUND=0
            SECOND_FOUND=0
            for argument in "$@"; do
                [ "$argument" != "$TD_FIRST_PATH" ] || FIRST_FOUND=1
                [ "$argument" != "$TD_SECOND_PATH" ] || SECOND_FOUND=1
            done
            [ "$FIRST_FOUND$SECOND_FOUND" = 11 ] || exit 100
        fi
        exit "${TD_SIM_EXIT:-0}"
    fi
    printf '%s\n' "$@" > "$TD_APT_LOG"
    printf '%s\n' "DEBIAN_FRONTEND=$DEBIAN_FRONTEND" >> "$TD_APT_LOG"
    exit "${TD_APT_EXIT:-0}"
    """ + "\n");
var debLocal = Path.Combine(testRoot, "test' $(printf injected);`echo bad`.deb");
File.WriteAllText(debLocal, "fake");
var deb = unixRoot + "/" + Path.GetFileName(debLocal);
var secondDebLocal = Path.Combine(testRoot, "second пакет $(echo literal).deb");
File.WriteAllText(secondDebLocal, "fake");
var secondDeb = unixRoot + "/" + Path.GetFileName(secondDebLocal);
var aptLog = Path.Combine(testRoot, "apt-arguments.txt");
if (File.Exists(aptLog)) File.Delete(aptLog);
int checks = 0;

(int Code, string Out, string Err) Run(string script, params (string Key, string Value)[] environment)
{
    var scriptFile = Path.Combine(testRoot, "current-test.sh");
    // Root is simulated only for local tests. The production script retains the real UID check.
    File.WriteAllText(scriptFile, "id() { printf '%s\\n' \"${TD_UID:-0}\"; }\n" + script.Replace("/var/jb", rootless));
    var start = new ProcessStartInfo(bash) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add("--noprofile");
    start.ArgumentList.Add("--norc");
    start.ArgumentList.Add(scriptFile);
    start.Environment["TD_APT_LOG"] = unixRoot + "/apt-arguments.txt";
    start.Environment["TD_SIM_LOG"] = unixRoot + "/simulation-arguments.txt";
    start.Environment["TD_FIRST_PATH"] = deb;
    start.Environment["TD_SECOND_PATH"] = secondDeb;
    start.Environment["MSYS_NO_PATHCONV"] = "1";
    foreach (var (key, value) in environment) start.Environment[key] = value;
    using var process = Process.Start(start)!;
    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(15000)) { process.Kill(true); throw new Exception("Shell test timeout."); }
    return (process.ExitCode, stdoutTask.Result, stderrTask.Result);
}

void Check(bool ok, string description)
{
    if (!ok) throw new Exception(description);
    checks++;
    Console.WriteLine("PASS " + description);
}

var chmod = Run("chmod +x " + DebWorkflow.Quote(rootless + "/usr/bin/dpkg") + " " + DebWorkflow.Quote(rootless + "/usr/bin/dpkg-deb") + " " + DebWorkflow.Quote(rootless + "/usr/bin/dpkg-query") + " " + DebWorkflow.Quote(rootless + "/usr/bin/apt-get"));
Check(chmod.Code == 0, "Create executable fake package tools");
var result = Run(DebWorkflow.GetPreflightScript(deb));
Check(result.Code == 0 && result.Out.Contains("TROLLDOCK_PREFLIGHT:ready"), "Rootless package preflight succeeds: " + result.Err);
Check(result.Out.Contains("TROLLDOCK_META:JailbreakMode=rootless") && result.Out.Contains("TROLLDOCK_META:Version=1.2.3-4"), "Metadata is parseable");
Check(!File.Exists(aptLog), "Preflight never runs a mutating apt operation");
Check(File.ReadAllLines(Path.Combine(testRoot, "simulation-arguments.txt")).Contains("--no-remove"), "Dependency simulation also forbids removals");
result = Run(DebWorkflow.GetPreflightScript(deb), ("TD_ARCH", "iphoneos-arm"));
Check(result.Code != 0 && result.Err.Contains("ARCH_MISMATCH"), "Rootful package is rejected on rootless bootstrap");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_UID", "501"));
Check(result.Code != 0 && result.Err.Contains("ROOT_REQUIRED") && !File.Exists(aptLog), "Non-root rejected before install");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_DEVICE_ARCH", "iphoneos-arm64e"));
Check(result.Code != 0 && result.Err.Contains("UNSUPPORTED_BOOTSTRAP") && !File.Exists(aptLog), "Unexpected bootstrap architecture rejected");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_PACKAGE", "bad\nTROLLDOCK_META:spoof=yes"));
Check(result.Code != 0 && result.Err.Contains("INVALID_METADATA") && !File.Exists(aptLog), "Multiline package metadata rejected before install");
result = Run(DebWorkflow.GetPreflightScript(deb), ("TD_ARCH", "all"));
Check(result.Code == 0, "Architecture-independent package accepted");
result = Run(DebWorkflow.GetPreflightScript(unixRoot + "/missing.deb"));
Check(result.Code != 0 && result.Err.Contains("DEB_NOT_FOUND"), "Missing transfer rejected");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_SIM_EXIT", "100"));
Check(result.Code == 100 && result.Err.Contains("APT_PREFLIGHT_FAILED") && !File.Exists(aptLog), "Dependency simulation failure prevents real installation");
result = Run(DebWorkflow.GetInstallScript(deb));
Check(result.Code == 0 && result.Out.Contains("TROLLDOCK_RESULT:installed"), "Installation success reported only on apt success");
var aptArgs = File.ReadAllLines(aptLog);
Check(aptArgs.Contains(deb), "Shell metacharacters preserved as one literal path argument");
Check(aptArgs.Contains("--no-remove") && aptArgs.Contains("Dpkg::Options::=--force-confold") && aptArgs.Contains("DEBIAN_FRONTEND=noninteractive"), "Removal blocked and existing conffiles retained");
Check(!aptArgs.Any(x => x is "update" or "--force-yes" or "--allow-unauthenticated" or "--fix-broken"), "No repository update, insecure override or repair fallback");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_APT_EXIT", "100"));
Check(result.Code == 100 && result.Err.Contains("APT_FAILED") && !result.Out.Contains("TROLLDOCK_RESULT:installed"), "APT failure preserved and never reported as success");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_STATUS", "install ok half-configured"));
Check(result.Code != 0 && result.Err.Contains("VERIFY_FAILED") && !result.Out.Contains("TROLLDOCK_RESULT:installed"), "Half-configured package never reported as success");
result = Run(DebWorkflow.GetInstallScript(deb), ("TD_VERSION", "9.9"));
Check(result.Code != 0 && result.Err.Contains("VERSION_MISMATCH") && !result.Out.Contains("TROLLDOCK_RESULT:installed"), "Unexpected installed version never reported as success");
result = Run(DebWorkflow.GetRespringScript());
Check(result.Code != 0 && result.Err.Contains("RESPRING_UNAVAILABLE"), "Missing sbreload does not trigger alternate reboot commands");
bool rejected = false;
try { DebWorkflow.GetInstallScript("relative.deb"); } catch (ArgumentException) { rejected = true; }
Check(rejected, "Relative install paths rejected");
rejected = false;
try { DebWorkflow.GetPreflightScript("/tmp/name\nnext.deb"); } catch (ArgumentException) { rejected = true; }
Check(rejected, "Newline in remote path rejected");
File.Delete(aptLog);
result = Run(DebWorkflow.GetBatchPreflightScript([deb, secondDeb]), ("TD_REQUIRE_PAIR", "1"));
Check(result.Code == 0 && result.Out.Contains("TROLLDOCK_PREFLIGHT:ready"), "Batch dependency simulation receives both local packages together");
Check(!File.Exists(aptLog), "Batch preflight does not install packages");
var simulationArgs = File.ReadAllLines(Path.Combine(testRoot, "simulation-arguments.txt"));
Check(simulationArgs.Count(value => value == deb) == 1 && simulationArgs.Count(value => value == secondDeb) == 1,
    "Batch simulation preserves Unicode and shell metacharacter paths as individual arguments");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_REQUIRE_PAIR", "1"), ("TD_SECOND_ARCH", "iphoneos-arm"));
Check(result.Code != 0 && result.Err.Contains("ARCH_MISMATCH") && !File.Exists(aptLog), "Incompatible second package prevents the whole mutating transaction");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_SECOND_PACKAGE", "com.example.tweak"));
Check(result.Code != 0 && result.Err.Contains("DUPLICATE_PACKAGE") && !File.Exists(aptLog), "Two versions of the same package are rejected before APT installation");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_SIM_EXIT", "100"));
Check(result.Code == 100 && !File.Exists(aptLog), "Batch dependency failure prevents mutation");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_REQUIRE_PAIR", "1"));
Check(result.Code == 0, "Both packages install in a successful shared transaction: " + result.Err);
aptArgs = File.ReadAllLines(aptLog);
Check(aptArgs.Count(value => value == deb) == 1 && aptArgs.Count(value => value == secondDeb) == 1 && aptArgs.Count(value => value == "install") == 1,
    "One mutating APT call receives both local package paths");
var batch = DebWorkflow.ParseBatchResult([debLocal, secondDebLocal], result.Code, result.Out, result.Err);
Check(batch.Success && batch.Items.Count == 2 && batch.Items.All(item => item.Installed), "Batch reports success only after checking every package version and status");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_APT_EXIT", "100"), ("TD_SECOND_STATUS", "install ok half-configured"));
batch = DebWorkflow.ParseBatchResult([debLocal, secondDebLocal], result.Code, result.Out, result.Err);
Check(result.Code == 100 && !batch.Success && batch.Items[0].Installed && !batch.Items[1].Installed && batch.Error!.Contains("APT"),
    "APT failure returns independently verified partial package results");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_SECOND_INSTALLED_VERSION", "1.0"));
batch = DebWorkflow.ParseBatchResult([debLocal, secondDebLocal], result.Code, result.Out, result.Err);
Check(result.Code != 0 && !batch.Success && batch.Items[0].Installed && !batch.Items[1].Installed,
    "APT zero exit does not hide a wrong installed version in the second package");
result = Run(DebWorkflow.GetBatchInstallScript([deb, secondDeb]), ("TD_APT_EXIT", "100"));
batch = DebWorkflow.ParseBatchResult([debLocal, secondDebLocal], result.Code, result.Out, result.Err);
Check(!batch.Success && batch.Items.All(item => item.Installed) && batch.Error != null,
    "APT failure remains visible even when all selected versions are present");
rejected = false;
try { DebWorkflow.ParseBatchResult([debLocal, secondDebLocal], 0, "TROLLDOCK_BATCH_VERIFY_BEGIN\nTROLLDOCK_BATCH_ITEM:0:installed\nTROLLDOCK_BATCH_COMPLETE:0\n", ""); }
catch (IOException) { rejected = true; }
Check(rejected, "Incomplete per-package verification is never presented as success");
rejected = false;
try { DebWorkflow.ParseBatchResult([debLocal], 0, "TROLLDOCK_BATCH_VERIFY_BEGIN\nTROLLDOCK_BATCH_ITEM:0:installed\nTROLLDOCK_BATCH_ITEM:0:installed\nTROLLDOCK_BATCH_COMPLETE:0\n", ""); }
catch (IOException) { rejected = true; }
Check(rejected, "Duplicate per-package verification markers are rejected");
rejected = false;
try { DebWorkflow.GetBatchInstallScript([]); } catch (ArgumentException) { rejected = true; }
Check(rejected, "Empty package batches rejected");
rejected = false;
try { DebWorkflow.GetBatchInstallScript([deb, deb]); } catch (ArgumentException) { rejected = true; }
Check(rejected, "Repeated remote paths rejected");
Check(File.ReadAllText(debLocal) == "fake" && File.ReadAllText(secondDebLocal) == "fake", "Local DEB source files remain unchanged");
Console.WriteLine($"{checks} checks passed using fake tools only. No device contacted.");

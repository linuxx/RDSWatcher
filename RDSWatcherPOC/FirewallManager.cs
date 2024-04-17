using System;
using System.Diagnostics;
using System.Linq;
using System.Timers;

namespace RDSWatcherPOC
{
    public class FirewallManager
    {
        private DatabaseManager dbManager { get; set; }
        private Timer cleanupTimer { get; set; }
        private Logger objLogger { get; set; }

        public FirewallManager(DatabaseManager dbManager, Logger logger)
        {
            objLogger = logger;
            this.dbManager = dbManager;
            SetupCleanupTimer();
            CleanupDatabase();
        }

        public void AddFirewallRule(string ip)
        {
            dbManager.AddOrUpdateIp(ip);
            UpdateFirewallRules();
        }

        public void UpdateFirewallRules()
        {
            var ips = dbManager.GetAllIPs();
            objLogger.Log($"Updating the firewall rule with {ips.Count} IP(s)", Logger.LogType.Info);
            string ipList = string.Join(",", ips.Select(x => x.IP));

            if (string.IsNullOrEmpty(ipList))
                ipList = "0.0.0.0"; // Default to blocking no IP if the list is empty

            string cmd = $"/c netsh advfirewall firewall set rule name=\"BlockIPs\" new remoteip={ipList} dir=in action=block enable=yes";
            ExecuteCommand(cmd);
        }

        private void SetupCleanupTimer()
        {
            cleanupTimer = new Timer(3600000); // Executes every hour
            cleanupTimer.Elapsed += (sender, e) => CleanupDatabase();

            cleanupTimer.Enabled = true;
        }

        private void CleanupDatabase()
        {
            objLogger.Log($"Running CleanupDatabase", Logger.LogType.Info);
            dbManager.CleanupDatabase();
            UpdateFirewallRules();
        }

        private void ExecuteCommand(string cmdText)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("cmd.exe", cmdText)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            objLogger.Log($"Command text was: {cmdText}", Logger.LogType.Debug);

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                    string errors = process.StandardError.ReadToEnd();
                    if (!string.IsNullOrEmpty(errors))
                    {
                        objLogger.Log("Error updating firewall rules: " + errors, Logger.LogType.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                objLogger.Log($"Couldn't update firewall rules: " + ex.Message, Logger.LogType.Error);
            }
            


        }


    }
}

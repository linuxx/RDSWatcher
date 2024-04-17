using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using Dapper;
using System.IO;
using System.Diagnostics;

namespace RDSWatcherPOC
{
    public class DatabaseManager
    {
        private const string DbFileName = "FirewallData.db";
        private const string DbConnectionString = "Data Source=" + DbFileName;
        private int cleanupAgeHours; // Variable to hold the age limit
        private Logger objLogger { get;set; }

        public DatabaseManager(int ageHours, Logger logger)
        {
            objLogger = logger;
            cleanupAgeHours = ageHours;
            InitializeDatabase();
            
        }

        private void InitializeDatabase()
        {
            if (!File.Exists(DbFileName))
            {
                try
                {
                    SQLiteConnection.CreateFile(DbFileName);
                    using (var connection = new SQLiteConnection(DbConnectionString))
                    {
                        connection.Open();
                        var tableCommand = @"
                    CREATE TABLE IF NOT EXISTS BlockedIPs (
                        IP TEXT PRIMARY KEY,
                        TimeBlocked DATETIME NOT NULL
                    )";
                        connection.Execute(tableCommand);
                    }
                }
                catch(Exception ex)
                {
                    objLogger.Log("Failed to create database: " + ex.Message, Logger.LogType.Error);
                    Environment.Exit(0);
                }
            }
        }

        

        public void AddOrUpdateIp(string ip)
        {
            using (var connection = new SQLiteConnection(DbConnectionString))
            {
                var existingIp = connection.QuerySingleOrDefault<IPBlockEntry>("SELECT * FROM BlockedIPs WHERE IP = @IP", new { IP = ip });
                if (existingIp != null)
                {
                    connection.Execute("UPDATE BlockedIPs SET TimeBlocked = @Time WHERE IP = @IP", new { Time = DateTime.UtcNow, IP = ip });
                }
                else
                {
                    connection.Execute("INSERT INTO BlockedIPs (IP, TimeBlocked) VALUES (@IP, @Time)", new { IP = ip, Time = DateTime.UtcNow });
                }
            }
        }

        public void CleanupDatabase()
        {
            if(cleanupAgeHours > 0) //setting to 0 disables this
            {
                objLogger.Log("Aging out IPs", Logger.LogType.Debug);
                using (var connection = new SQLiteConnection(DbConnectionString))
                {
                    connection.Execute("DELETE FROM BlockedIPs WHERE strftime('%s', 'now') - strftime('%s', TimeBlocked) > @Lifetime", new { Lifetime = cleanupAgeHours * 3600 });
                }
            }
            
        }

        public List<IPBlockEntry> GetAllIPs()
        {
            using (var connection = new SQLiteConnection(DbConnectionString))
            {
                return connection.Query<IPBlockEntry>("SELECT * FROM BlockedIPs").ToList();
            }
        }

    }

}

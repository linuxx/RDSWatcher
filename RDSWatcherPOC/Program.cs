using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Timers;
using System.Net;

namespace RDSWatcherPOC
{
    internal class Program
    {

        static List<MyEvents> objEventsList = new List<MyEvents>();
        static List<MyEvents> objSlash24s = new List<MyEvents>();
        static bool blSlash24s = false;
        static int intSlas24Limit = 100;
        static int intLimit = 30; //default 30 bad logins
        static int intAge = 24; //default 24hrs

        //logger
        static Logger.Mode logMode;
        static string logPath;

        static DatabaseManager objDB { get; set; }
        static FirewallManager objFW { get; set; }
        static Logger objLogger { get; set; }


        static void Main(string[] args)
        {
            //set an initial log mode
            logMode = Logger.Mode.Normal;

            //parse the given arguments
            ParseCommandLineArguments(args);

            // Initialize logger with the mode and path
            objLogger = new Logger(logMode, logPath); 

            // Log initial configuration settings
            LogInitialSettings(); 

            //setup a bleed timer
            Timer objBleed = new Timer(60000);
            objBleed.Elapsed += ObjBleed_Elapsed;
            objBleed.Enabled = true;

            //the two managers
            objDB = new DatabaseManager(intAge, objLogger);
            objFW = new FirewallManager(objDB, objLogger);

            //get the logs going
            SetupEventLogWatcher();
        }

        /// <summary>
        /// This parses the command line args 
        /// </summary>
        static void ParseCommandLineArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "/age":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int age))
                        {
                            intAge = age;
                        }
                        i++; // Skip next argument
                        break;
                    case "/limit":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int limit))
                        {
                            intLimit = limit;
                        }
                        i++; // Skip next argument
                        break;
                    case "/debug":
                        logMode = Logger.Mode.Debug;
                        break;
                    case "/24":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int slash24limit))
                        {
                            intSlas24Limit = slash24limit;
                            blSlash24s = true;
                        }
                        i++; // Skip next argument
                        break;
                    case "/logpath":
                        if (i + 1 < args.Length)
                        {
                            logPath = args[i + 1];
                        }
                        i++; // Skip next argument
                        break;
                    case "/help":
                        DisplayHelp();
                        Environment.Exit(0);
                        break;
                }
            }
        }

        /// <summary>
        /// this is to bleed off ticks on IP hits after no action has happend in over the 5 minutes, runs every minute
        /// </summary>
        private static void ObjBleed_Elapsed(object sender, ElapsedEventArgs e)
        {
            //the regular list
            List<MyEvents> objSubList = objEventsList.Where(
                evt => evt.UpdateTime < DateTime.Now.AddMinutes(-5)).ToList();
            //the /24s
            List<MyEvents> objSlash24s = objEventsList.Where(
                evt => evt.UpdateTime < DateTime.Now.AddMinutes(-5)).ToList();

            objSubList.AddRange(objSlash24s); //concat

            if (objSubList.Count > 0) 
            {
                objLogger.Log($"Bleeding off {objSubList.Count} IP(s)", Logger.LogType.Debug);
                foreach (MyEvents objEvent in objSubList)
                {
                    if (objEvent.Count > 0)
                    {
                        objEvent.Count--;
                    }
                    else
                    {
                        objEventsList.Remove(objEvent);
                    }
                }
            }
        }

        /// <summary>
        /// Shows the help menu
        /// </summary>
        static void DisplayHelp()
        {
            Console.WriteLine("Usage: RDSWatcherPOC [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  /age [hours]      Set the length in hours to age out firewall rules.");
            Console.WriteLine("  /limit [number]   Set the failed login limit before a firewall rule is added.");
            Console.WriteLine("  /24 [number]      Set the limit for subnet blocking.");
            Console.WriteLine("  /debug            Enable debug logging mode.");
            Console.WriteLine("  /logpath [path]   Specify the path for the log file.");
        }


        /// <summary>
        /// Outputs the initial settings 
        /// </summary>
        static void LogInitialSettings()
        {
            objLogger.Log($"Subnet blocking is {(blSlash24s ? $"enabled, limit: {intSlas24Limit}" : "disabled")}", Logger.LogType.Info);
            objLogger.Log($"Age out is set to: {(intAge > 0 ? $"{intAge} hrs" : "Never")}", Logger.LogType.Info);
            objLogger.Log($"Login attempt limit is set to: {intLimit}", Logger.LogType.Info);
            if (logPath != null)
            {
                objLogger.Log($"Log path is set to: {logPath}", Logger.LogType.Info);
            }
        }


        /// <summary>
        /// Setup the event log watcher
        /// </summary>
        static void SetupEventLogWatcher()
        {
            string query = "*[System/EventID=4625]";
            EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
            using (EventLogWatcher watcher = new EventLogWatcher(eventsQuery))
            {
                watcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventLogEventRead);
                watcher.Enabled = true;

                Console.WriteLine("Listening for event 4625 in Security logs. Press any key to exit.");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Read the event
        /// </summary>
        static void EventLogEventRead(object obj, EventRecordWrittenEventArgs arg)
        {
            if (arg.EventRecord == null || arg.EventRecord.Id != 4625)
                return;

            try
            {
                string sourceAddress = arg.EventRecord.Properties[19].Value.ToString();
                string accountName = arg.EventRecord.Properties[5].Value.ToString().ToLower();

                // Process individual IP
                ProcessEvent(sourceAddress, accountName, objEventsList, intLimit, "/32", false);

                // Optionally process subnet if enabled
                if (blSlash24s)
                {
                    string subnetAddress = SubNetIP(sourceAddress);
                    ProcessEvent(subnetAddress, "", objSlash24s, intSlas24Limit, "/24", true);
                }
            }
            catch (Exception ex)
            {
                objLogger.Log("Had issues dealing with this event: " + ex.Message, Logger.LogType.Error);
            }
        }

        /// <summary>
        /// handles the acutal events
        /// </summary>
        static void ProcessEvent(string ipAddress, string username, List<MyEvents> eventList, int limit, string cidr, bool isSubnet)
        {
            MyEvents eventObj = eventList.FirstOrDefault(e => e.IP == ipAddress);

            //is this a new entry, or just another?!
            if (eventObj != null)
            {
                eventObj.Count++;
                eventObj.UpdateTime = DateTime.Now;

                if (isSubnet) //if this isa subnet, we log something different
                {
                    objLogger.Log($"Logon failure from Subnet {ipAddress}. Attempt count: {eventObj.Count}", Logger.LogType.Debug);
                }
                else
                {
                    objLogger.Log($"Logon failure from IP {ipAddress} for account: {username}. Attempt count: {eventObj.Count}", Logger.LogType.Debug);
                }

                if (eventObj.Count >= limit) //did we hit the limit, then block
                {
                    if (isSubnet)
                    {
                        objLogger.Log($"Blocking traffic from Subnet {ipAddress} after {eventObj.Count} failed logins", Logger.LogType.Info);
                    }
                    else
                    {
                        objLogger.Log($"Blocking traffic from IP {ipAddress} after {eventObj.Count} failed logins", Logger.LogType.Info);
                    }
                    objFW.AddFirewallRule(ipAddress + cidr); //block it
                    eventList.Remove(eventObj); // Remove the event after blocking
                }
            }
            else
            {
                // Create a new event if it doesn't exist
                eventObj = new MyEvents(1, ipAddress, username) { UpdateTime = DateTime.Now };
                eventList.Add(eventObj);

                if (isSubnet)
                {
                    objLogger.Log($"New logon failure from Subnet {ipAddress}. Attempt count: 1", Logger.LogType.Debug);
                }
                else
                {
                    objLogger.Log($"New logon failure from IP {ipAddress} for account: {username}. Attempt count: 1", Logger.LogType.Debug);
                }
            }
        }


        /// <summary>
        /// Converts a ip to a subnet
        /// </summary>
        /// <param name="ipAddress">The IP to convert</param>
        /// <returns></returns>
        static string SubNetIP(string ipAddress)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipAddress);
                byte[] byteIP = ip.GetAddressBytes();
                byteIP[3] = 0; // Set the last byte to 0 for /24 network
                return new IPAddress(byteIP).ToString();
            }
            catch
            {
                return ipAddress; // Return original on parse failure
            }
        }


    }
}

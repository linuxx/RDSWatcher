using System;
using System.IO;

namespace RDSWatcherPOC
{
    public class Logger
    {
        StreamWriter objFile { get; set; }
        public Mode objMode { get; set; }

        /// <summary>
        /// Initiate the logger
        /// </summary>
        /// <param name="mode">Logging mode</param>
        /// <param name="path">Path to the log file</param>
        public Logger(Mode mode, string path = null)
        {
            objMode = mode;
            if (path != null)
            {
                objFile = new StreamWriter(path, true) { AutoFlush = true };
            }

            Log("Starting up RDS Logger", LogType.Info);
            Log("/help gives you command line arguments", LogType.Info);
        }

        /// <summary>
        /// Logs a message if the conditions based on the mode are met.
        /// </summary>
        /// <param name="message">The message to log</param>
        /// <param name="type">The type of log message</param>
        public void Log(string message, LogType type)
        {
            string timeStamp = DateTime.Now.ToString("MM-dd-yyyy HH:mm:ss");
            if (ShouldLog(type))
            {
                string formattedMessage = $"{timeStamp} -- {type} -- {message}";
                Console.WriteLine(formattedMessage);
                if (objFile != null)
                {
                    objFile.WriteLine(formattedMessage);
                }
            }
        }

        /// <summary>
        /// Determines if the message should be logged based on the current mode and log type.
        /// </summary>
        /// <param name="type">Type of log message</param>
        /// <returns>true if the message should be logged; otherwise, false.</returns>
        private bool ShouldLog(LogType type)
        {
            if (objMode == Mode.Debug)
            {
                return true; // In Debug mode, log everything.
            }
            else
            {
                // In Normal mode, only log Warnings, Errors, and Information
                return type == LogType.Warning || type == LogType.Error || type == LogType.Info;
            }
        }

        /// <summary>
        /// The entry type
        /// </summary>
        public enum LogType
        {
            Error,
            Warning,
            Info,
            Debug
        }

        /// <summary>
        /// What mode is the logging in
        /// </summary>
        public enum Mode
        {
            Debug,
            Normal
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RDSWatcherPOC
{
    public class MyEvents
    {
        public int Count { get; set; }
        public string IP { get; set; }
        public string Username { get; set; }
        public DateTime UpdateTime { get; set; }

        public MyEvents(int count, string iP, string username)
        {
            Count = count;
            IP = iP;
            Username = username;
            UpdateTime = DateTime.Now;
        }

    }
}

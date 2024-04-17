using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RDSWatcherPOC
{
    public class IPBlockEntry
    {
        public string IP { get; set; }
        public DateTime TimeBlocked { get; set; }
    }
}

//Copyright(c) 2024, Darren Banfi
//All rights reserved.
//
//This source code is licensed under the BSD-style license found in the
//LICENSE file in the root directory of this source tree. 

//Class to support DataGrid view builder

namespace Scan_Network
{
    public class NetworkDevice
    {
        public string? IP { get; set; }
        public string? MACAddress { get; set; }
        public string? MACVendor { get; set; }

        public string? Uptime { get; set; }
        public string? Serial {  get; set; }
        public string? Model { get; set; }
        public string? Name { get; set; }    
        public string? Info { get; set; }
        public long Ping { get; set; }
        public string? Port80 { get; set; }

    }

}

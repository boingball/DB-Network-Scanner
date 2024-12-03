//Copyright(c) 2024, Darren Banfi
//All rights reserved.
//
//This source code is licensed under the BSD-style license found in the
//LICENSE file in the root directory of this source tree. 
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Newtonsoft.Json.Linq;
using RestSharp;
using Scan_Network.Properties;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Navigation;
using System.Xml.Linq;

namespace Scan_Network
{
    public partial class MainWindow : Window
    {
        // MACVendor Support - MACVendors.xml from Cisco vendorMacs.xml 
        string? MacVendor;
        XDocument doc = XDocument.Load("MACVendors.xml");
        //Deepscan Ping Websocket to see if it responds
        bool deepscan;

        public MainWindow()
        {
            InitializeComponent();
            string IPDetected = GetLocalIPAddress();
            TextIP.Text = IPDetected;
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            //All the magic from the Scan button
            //Turn on the GreenLED Circle
            this.GreenLED.Visibility = Visibility.Visible;
            this.GreenLED.Refresh();
            //Set base of SNMP Scan
            string community = "public";
            int port = 161;
            string oid = "1.3.6.1.2.1.1.1.0"; // OID for sys detection
            // Define the range of IP addresses to scan
            //GetLocal IP
            string IPDetected = GetLocalIPAddress();
            IPAddress address;
            if (TextIP.Text != null) {
                if (IPAddress.TryParse(TextIP.Text, out address))
                {
                    //Valid IP, with address containing the IP
                    IPDetected = TextIP.Text;
                }
                else
                {
                    //Invalid IP
                    TextIP.Text = "Invalid IP";
                    this.GreenLED.Visibility = Visibility.Hidden;
                    TextIP.Refresh();
                    return;
                }

             }

            int IndexOfSubnet = IPDetected.LastIndexOf(".");
            //Just getting the 1-254 of IP Addressess
            string baseIp = IPDetected.Substring(0, IndexOfSubnet + 1);
            int startIp = 1;
            int endIp = 254;
            List<NetworkDevice> networkdevice = new List<NetworkDevice>();
            // Create a list of IP addresses to scan
            var ipAddresses = Enumerable.Range(startIp, endIp - startIp + 1)
                                        .Select(i => baseIp + i)
                                        .ToList();
            // 2nd Scan IP List
            var secondIplist = new List<string>();
            var tasks = new List<Task>();

            foreach (var ipAddress in ipAddresses)
            {
                tasks.Add(Task.Run(async () =>
                {
                    
                    await ScanIPAddress(ipAddress, port, oid, community, networkdevice, secondIplist);
                }));
            }

            await Task.WhenAll(tasks);

            // 2nd Scan
            foreach (var ip in secondIplist)
            {
                oid = "1.3.6.1.2.1.1.1.0";
                string infoName = GetSNMPDetails(ip, port, oid, community);
                string reconstructedIP = SantitiseIP(ip.ToString());
                networkdevice.Add(new NetworkDevice()
                {
                    IP = reconstructedIP.ToString(),
                    MACAddress = getMacByIp(ip),
                    Uptime = "1",
                    Serial = "0",
                    Name = infoName,
                    Model = "0",
                    Info = infoName,
                    Ping = 0
                });
            }

            this.networkDataGrid.ItemsSource = networkdevice;
            foundDevices.Content = "Found Devices: " + networkdevice.Count;
            RefreshAndSortDataGrid();
        }

        private async Task ScanIPAddress(string ipAddress, int port, string oid, string community, List<NetworkDevice> networkdevice, List<string> secondIplist)
        {
            try
            {
                var result = Messenger.Get(VersionCode.V2,
                      new IPEndPoint(System.Net.IPAddress.Parse(ipAddress), port),
                      new OctetString(community),
                      new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                      10);
                //Need to ping to get MAC
                Ping p = new Ping();
                PingReply r = p.Send(ipAddress);
                long pingtime = r.Status == IPStatus.Success ? r.RoundtripTime : -999;

                string macaddress = getMacByIp(ipAddress);
                string MAVVLU = MACVendorLookup(macaddress);

                foreach (var variable in result)
                {
                    //SNMP Walking for each result
                    //Get Uptime
                    string uptimeoid = "1.3.6.1.2.1.1.3.0";
                    var uptime = GetSNMPDetails(ipAddress, port, uptimeoid, community);
                    //Get Serial Number
                    string deviceSerialOid = "1.3.6.1.2.1.47.1.1.1.1.11.1";
                    var serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);
                    if (serialNumber == "NoSuchObject")
                    {
                        deviceSerialOid = "1.3.6.1.2.1.43.5.1.1.17.1";
                        serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);
                    }
                    if (serialNumber == "" || serialNumber == "NoSuchObject")
                    {
                        deviceSerialOid = "1.3.6.1.4.1.318.1.1.1.1.2.3.0";
                        serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);

                    }
                    if (serialNumber == "" || serialNumber == "NoSuchObject")
                    {
                        deviceSerialOid = "1.3.6.1.4.1.11.2.36.1.1.2.9.0";
                        serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);

                    }
                    if (serialNumber == "" || serialNumber == "NoSuchObject")
                    {
                        deviceSerialOid = "1.0.8802.1.1.2.1.5.4795.1.2.5.0";
                        serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);

                    }
                    if (serialNumber == "" || serialNumber == "NoSuchObject")
                    {
                        deviceSerialOid = "1.3.6.1.4.1.295";
                        serialNumber = GetSNMPDetails(ipAddress, port, deviceSerialOid, community);

                    }
                    //Serial Number End
                    //Get Model Number
                    string modelOid = "1.3.6.1.2.1.47.1.1.1.1.2.1";
                    var modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.1.2.0";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.25.3.2.1.3.1";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.33.1.1.2.0";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.0.8802.1.1.2.1.5.4795.1.2.7.0";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.43.5.1.1.16.1";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.25.3.2.1.3.1";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.47.1.1.1.1.13.1";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    if (modelName == "NoSuchObject")
                    {
                        modelOid = "1.3.6.1.2.1.1.5.0";
                        modelName = GetSNMPDetails(ipAddress, port, modelOid, community);
                    }
                    //Model Number End
                    //Get Name of Device
                    string NameOID = "1.3.6.1.2.1.1.5.0";
                    var deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.2.1.47.1.1.1.1.7.1";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.4.1.318.1.1.1.1.2.5.0";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.2.1.1.5.0";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.2.1.1.1.0";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.4.1.18334.1.1.2.1.5.7.20.1.1.2.1";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    if (deviceName == "NoSuchObject")
                    {
                        NameOID = "1.3.6.1.2.1.1.1.0";
                        deviceName = GetSNMPDetails(ipAddress, port, NameOID, community);
                    }
                    //Device Name End
                    //Santitise uptime (Day.D:Min:Sec.Sec)
                    //Get the Day first
                    int dayPart = uptime.IndexOf(".");
                    string dayReal = uptime.Substring(0, dayPart);
                    string TCPString = "NA";
                    //string HTTPPage = "";
                    //Deepscan ticked - try a TCP Connect on port 80
                    if (deepscan == true)
                    {
                        try
                        {
                            var client = new TcpClient();
                            IAsyncResult TCPResult = client.BeginConnect(ipAddress, 80, null, null);
                            TCPResult.AsyncWaitHandle.WaitOne();
                            TCPResult.AsyncWaitHandle.Close();
                            client.EndConnect(TCPResult);
                            TCPString = client.Connected.ToString();

                        }
                        catch { TCPString = "NA"; }

                    }
                    //Convert IP Addresses, 0xx becomes an Octal in a browser
                    string reconstructedIP = SantitiseIP(ipAddress.ToString());
                    //Add our network device to the list
                    networkdevice.Add(new NetworkDevice()
                    {
                        IP = reconstructedIP,
                        MACAddress = macaddress,
                        MACVendor = MAVVLU,
                        Uptime = dayReal,
                        Serial = serialNumber,
                        Name = deviceName,
                        Model = modelName,
                        Info = variable.Data.ToString(),
                        Ping = pingtime,
                        Port80 = TCPString
                    });
                }
            }
            catch (Exception ex)
            {
                //Catch all from SNMP failure
                string TCPString = "NA";
                //string HTTPPage = "";
                if (deepscan == true)
                {
                    try
                    {
                        var client = new TcpClient();
                        IAsyncResult TCPResult = client.BeginConnect(ipAddress, 80, null, null);
                        TCPResult.AsyncWaitHandle.WaitOne();
                        TCPResult.AsyncWaitHandle.Close();
                        client.EndConnect(TCPResult);
                        TCPString = client.Connected.ToString();


                    }
                    catch { TCPString = "NA"; }
                }
                // Handle any exceptions (e.g., timeouts, no response)
                //Check if we have a real device - add if we do.
                Ping myPing = new Ping();
                PingReply reply = myPing.Send(ipAddress, 50);
                string macaddress = getMacByIp(ipAddress);
                string MAVVLU = MACVendorLookup(macaddress);
                //Check for a device justincase it didn't response in the first timeout
                string deviceName = "";
                if (ex.ToString().Contains("System.Net.Sockets"))
                {
                    //Exception when pinging the Loop Back so set device name to Loopback
                    //deviceName = "Loop Back";
                }
                if (TCPString != "NA")
                {
                    deviceName = "Web Device";
                }
                if (reply.Status == IPStatus.Success)
                {
                    if (ex.ToString().Contains("System.InvalidOperation"))
                    {
                        //Second Scan List
                        secondIplist.Add(ipAddress);
                    }
                    else
                    {

                        var result = await SnipeITMACLookup(macaddress);
                        if (deviceName == "")
                        {
                            deviceName = result.assetTag;
                        }
                        string modelName = result.ModelName;
                        string serial = result.serialValue;
                        string reconstructedIP = SantitiseIP(ipAddress.ToString());
                        networkdevice.Add(new NetworkDevice()
                        {
                            IP = reconstructedIP.ToString(),
                            MACAddress = macaddress,
                            MACVendor = MAVVLU,
                            Uptime = "",
                            Serial = serial,
                            Name = deviceName,
                            Model = modelName,
                            Info = "_Pingable Device",
                            Ping = reply.RoundtripTime,
                            Port80 = TCPString
                        });
                    }

                }
            }
        }


        private void RefreshAndSortDataGrid()
        {   // Refresh data
            // Assuming data has been updated in your ObservableCollection
            // Get the default view of the data source
            ICollectionView collectionView = CollectionViewSource.GetDefaultView(networkDataGrid.ItemsSource);
            // Clear existing sort descriptions
            collectionView.SortDescriptions.Clear();
            // Apply new sort descriptions
            collectionView.SortDescriptions.Add(new SortDescription("Uptime", ListSortDirection.Descending));
            collectionView.SortDescriptions.Add(new SortDescription("Info", ListSortDirection.Descending));
            // Refresh the view to apply the sort
            collectionView.Refresh();
            this.GreenLED.Visibility = Visibility.Hidden;
            this.GreenLED.Refresh();
        }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            String URL = e.Uri.OriginalString;
            URL = URLIP(URL);
            String EndURL = "http://" + URL;
            Process.Start(new ProcessStartInfo(EndURL.ToString()) { UseShellExecute = true });
            e.Handled = true;
        }

        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }

        public string GetSNMPDetails(string ipaddress, int port, string oid, string community)
        {
            //Function to get SNMP details by OID
            var ipaddressParsed = System.Net.IPAddress.Parse(ipaddress);
            try
            {
                var snmpcheckresult = Messenger.Get(VersionCode.V2,
                           new IPEndPoint(ipaddressParsed, port),
                           new OctetString(community),
                           new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                           500);
                string snmpcheckresultData = snmpcheckresult.First().ToString();
                int snmpcheckresultIndex = snmpcheckresultData.IndexOf("Data");
                snmpcheckresultData = snmpcheckresultData.Substring(snmpcheckresultIndex + 6);
                if (snmpcheckresultData.Contains("1.3.6.1"))
                {
                    snmpcheckresultData = "NoSuchObject";
                }
                if (snmpcheckresultData.Contains("HPE"))
                {
                    snmpcheckresultData = "NoSuchObject";
                }
                if (snmpcheckresultData == null || snmpcheckresultData == "") { snmpcheckresultData = "NoSuchObject"; }
                return snmpcheckresultData;
            }
            catch (SnmpException ex)
            {
                // Handle SNMP-specific exceptions, e.g., timeout, invalid community string, etc.
                return($"SNMP Exception: {ex.Message}");
            }
            catch (SocketException ex)
            {
                // Handle network-related exceptions, e.g., unable to reach the device
                return ($"Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Handle any other exceptions that might occur
                return ($"General error: {ex.Message}");
            }

        }

        public string getMacByIp(string ip)
        {
            var macIpPairs = GetAllMacAddressesAndIppairs();
            int index = macIpPairs.FindIndex(x => x.IpAddress == ip);
            if (index >= 0)
            {
                return macIpPairs[index].MacAddress.ToUpper();
            }
            else
            {
                return "00-00-00-00-00-00";
            }
        }

        public List<MacIpPair> GetAllMacAddressesAndIppairs()
        {
            List<MacIpPair> mip = new List<MacIpPair>();
            System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
            pProcess.StartInfo.FileName = "arp";
            pProcess.StartInfo.Arguments = "-a ";
            pProcess.StartInfo.UseShellExecute = false;
            pProcess.StartInfo.RedirectStandardOutput = true;
            pProcess.StartInfo.CreateNoWindow = true;
            pProcess.Start();
            string cmdOutput = pProcess.StandardOutput.ReadToEnd();
            string pattern = @"(?<ip>([0-9]{1,3}\.?){4})\s*(?<mac>([a-f0-9]{2}-?){6})";

            foreach (Match m in Regex.Matches(cmdOutput, pattern, RegexOptions.IgnoreCase))
            {
                mip.Add(new MacIpPair()
                {
                    MacAddress = m.Groups["mac"].Value,
                    IpAddress = m.Groups["ip"].Value
                });
            }

            return mip;
        }
        public struct MacIpPair
        {
            public string MacAddress;
            public string IpAddress;
        }

        public string SantitiseIP(string ipAddress)
        {
            //Santitise iPaddress
            string realIP = ipAddress.ToString();
            //Find last subnet
            int lastSubnetLoc = realIP.LastIndexOf(".");
            string lastSubnet = realIP.Substring(lastSubnetLoc + 1);
            string paddedSubnet = lastSubnet.PadLeft(3, '0');
            string firstPartofIP = realIP.Substring(0, lastSubnetLoc + 1);
            string reconstructedIP = firstPartofIP + paddedSubnet;
            return reconstructedIP;
        }

        public string URLIP(string ipAddress)
        {

            //Santitise iPaddress
            string realIP = ipAddress.ToString();
            //Find last subnet
            int lastSubnetLoc = realIP.LastIndexOf(".");
            string lastSubnet = realIP.Substring(lastSubnetLoc + 1);
            if (lastSubnet.StartsWith("0")) {
                string replacedSubnet = lastSubnet.Substring(1);
                string firstPartofIP = realIP.Substring(0, lastSubnetLoc + 1);
                string reconstructedIP = firstPartofIP + replacedSubnet;
                return reconstructedIP;
            }
            else
            {
                return realIP;
            }
        }

        public string MACVendorLookup(string macAddress)
        {
            //Look for MACVendor via XML loaded in DOC
            string checkMac = macAddress.Replace("-", ":");
            checkMac = checkMac.Substring(0, 8);
            var query = doc
                .Root
                .Elements()
                .Where(e => e.Attribute("mac_prefix").Value == checkMac)
                .Select(e => e.Attribute("vendor_name"))
                .ToList();

            if (query.Count != 0) { MacVendor = query[0].Value.ToString(); } else { MacVendor = "Not Found"; }

            return MacVendor;
        }

        public static async Task<(string serialValue, string assetTag, string ModelName)> SnipeITMACLookup(string macAddress)
        {
            //Santize the MAC address so SnipeIT can search
            if (macAddress == "00-00-00-00-00-00")
            {
                return ("Not Found", "Not Found", "Not Found");
            }
            macAddress = macAddress.Replace("-", ":");

            if (Properties.Settings.Default.SnipeITSupport == true) {
            var options = new RestClientOptions("" + Properties.Settings.Default.SnipeITURL + "/api/v1/hardware?limit=1&offset=0&search=" + macAddress + "&sort=created_at&order=desc");
            var client = new RestClient(options);
            var request = new RestRequest("");
            request.AddHeader("accept", "application/json");
            //My Test API Key
            request.AddHeader("Authorization", "Bearer" + " " + Properties.Settings.Default.SnipeITPAT);
            var response = await client.GetAsync(request);
            if (response.IsSuccessful && response.Content is not null) { 
                try {
                string responseContent = response.Content.ToString();
            JObject jsonObject = JObject.Parse(responseContent);
            string serialValue = (string)jsonObject["rows"][0]["serial"];
            string assetTag = (string)jsonObject["rows"][0]["asset_tag"];
            string modelName = (string)jsonObject["rows"][0]["model"]["name"];
            if (assetTag == null) { assetTag = "Not Found"; }
            return (serialValue ?? "Not Found", assetTag ?? "Not Found", modelName ?? "Not Found");
                } catch { return ("Not Found", "Not Found", "Not Found"); }
            }
            else
            {
                return ("Not Found", "Not Found", "Not Found");
            }
            }
            return ("Not Found", "Not Found", "Not Found");
        }

        private void DeepScan_Checked(object sender, RoutedEventArgs e)
        {
            if (DeepScan.IsChecked == true) { deepscan = true; }

        }

        private void DeepScan_UnChecked(object sender, RoutedEventArgs e)
        {
            if (DeepScan.IsChecked == false) { deepscan = false; }

        }

        private void TextIP_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {

        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e)
        {
            // Create an instance of the Settings window
            Settings settingsWindow = new Settings();

            // Show the window
            settingsWindow.Show();
        }
    }
}
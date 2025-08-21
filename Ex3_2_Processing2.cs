using PacketDotNet;
using PacketDotNet.Ieee80211;
using Pass;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Timers;
namespace TestsSharpPcap
{

    public class Ex3_2_Process2
    {
        private static String ch_srcIP;

        private static String ch_dstIP;

        private static PacketDotNet.TcpPacket tcpPacket;

        private static IPPacket ipPacket;

        private static System.Net.IPAddress srcIp;// = ipPacket.SourceAddress;

        private static System.Net.IPAddress dstIp;// = ipPacket.DestinationAddress;

        private static DateTime dateCap;

        static int On_Arriv = 0;
        /// <summary>
        /// Object that is used to prevent two threads from accessing
        /// PacketQueue at the same time
        /// </summary>
        /// <param name="args">
        /// A <see cref="string"/>
        /// </param>
        private static readonly object QueueLock = new object();

        /// <summary>
        /// The queue that the callback thread puts packets in. Accessed by
        /// the background thread when QueueLock is held
        /// </summary>
        private static List<PacketDotNet.TcpPacket> PacketQueue = new List<PacketDotNet.TcpPacket>();

        private static Thread backgroundThread = new Thread(BackgroundThread);


        private static bool BackgroundThreadStop = false;
        /// <summary>
        /// The last time PcapDevice.Statistics() was called on the active device.
        /// Allow periodic display of device statistics
        /// </summary>
        /// <param name="args">
        /// A <see cref="string"/>
        /// </param>
        private static DateTime LastStatisticsOutput = DateTime.Now;
        /// <summary>
        /// Interval between PcapDevice.Statistics() output
        /// </summary>
        /// <param name="args">
        /// A <see cref="string"/>
        /// </param>
        private static TimeSpan LastStatisticsInterval = new TimeSpan(0, 0, 2);

        private static TimeSpan interval;// = now - LastStatisticsOutput;


        public void Main()
        {
            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}, Example3.BasicCap.cs", ver);


            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;
            //object jsWindow = Interop.ExecuteJavaScript("window");

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());


            var device = devices[i];
            string filter = "tcp and (port 80 or port 443)";

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);
            device.Filter = filter;
            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);
            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();
            BackgroundThreadStop = true;

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());
        }

        private static void BackgroundThread()
        {
            DateTime now = DateTime.Now;
            Console.WriteLine("BackgroundThreadDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" + now);
            while (!BackgroundThreadStop)
            {
                bool shouldSleep = true;

                lock (QueueLock)
                {
                    if (PacketQueue.Count != 0)
                    {
                        shouldSleep = false;
                    }
                }

                if (shouldSleep) //si packetQueue.Count = 0
                {
                    System.Threading.Thread.Sleep(250);
                }
                else // should process the queue si packetQueue.Count !> 0
                {
                    List<PacketDotNet.TcpPacket> ourQueue;
                    lock (QueueLock)
                    {
                        // swap queues, giving the capture callback a new one
                        ourQueue = PacketQueue;
                        PacketQueue = new List<PacketDotNet.TcpPacket>();
                    }

                    //Console.WriteLine("BackgroundThread: ourQueue.Count is {0}", ourQueue.Count);

                    foreach (var packet in ourQueue)
                    {
                        srcIp = ipPacket.SourceAddress;
                        dstIp = ipPacket.DestinationAddress;
                        Console.WriteLine("Date heure récupérée sur On_Arrival THREADDDDDDDDDDDDDDDDDD    BKR !!!!! : " + now);
                        Console.WriteLine("Date heure du packet BKR !!!!! : " + dateCap);
                        Console.WriteLine("CE QUI M'INTERESSE IP SRC BKR !!!!! : " + srcIp);
                        Console.WriteLine("CE QUI M'INTERESSE IP DST BKR !!!!! : " + dstIp);
                        Console.WriteLine("CE QUI M'INTERESSE backgroundThread.IsAlive " + backgroundThread.IsAlive);
                        Console.WriteLine();
                        Module1.Site_Connu(srcIp, dstIp);
                        Module1.IP_connu(ch_srcIP, ch_dstIP);
                    }
                }
            }
        }
        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            Console.WriteLine("device_OnPacketArrivalLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL");
            DateTime now = DateTime.Now;
            var time = e.Header.Timeval.Date;
            dateCap = time;
            var len = e.Data.Length;
            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);//+
            tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            if (tcpPacket != null)
            {
                ipPacket = (IPPacket)tcpPacket.ParentPacket;
                srcIp = ipPacket.SourceAddress;
                dstIp = ipPacket.DestinationAddress;
                lock (QueueLock)
                {
                    PacketQueue.Add(tcpPacket); //The queue that the callback thread puts packets in. Accessed by
                }
                ch_srcIP = (string)srcIp.ToString();
                ch_dstIP = (string)dstIp.ToString();
                //Console.WriteLine();
                if ((!backgroundThread.IsAlive) & (!(backgroundThread.ThreadState == System.Threading.ThreadState.Stopped)) & ((!(backgroundThread.ThreadState == System.Threading.ThreadState.Running))))
                {
                    backgroundThread.Start();
                }
             /*           else
            {
                Console.WriteLine("Pack Null");
            }*/
            }
        }
    }
}
        
        





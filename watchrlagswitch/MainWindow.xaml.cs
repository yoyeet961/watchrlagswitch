using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using WinDivertSharp;

namespace watchrlagswitch
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public uint packetLen;
        public bool started = false;
        Dictionary<string, bool> robloxfilter = new Dictionary<string, bool>();
        public bool isRoblox(string ip) // idk why people dont use this method
        {
            if (robloxfilter.ContainsKey(ip))
            {
                return robloxfilter[ip];
            }
            var files = Directory.GetFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Roblox", "logs"));
            foreach (var file in files)
            {
                try
                {
                    using (FileStream fs = new FileStream(
                        file,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite
                    ))
                    using (StreamReader reader = new StreamReader(fs))
                    {
                        string text = reader.ReadToEnd();
                        if (text.Contains(ip))
                        {
                            robloxfilter[ip] = true;
                            Debug.WriteLine($"{ip} is a roblox gameserver");
                            return true;
                        }
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
            robloxfilter[ip] = false;
            Debug.WriteLine($"{ip} is NOT a roblox gameserver");
            return false;
        }

        void FixIPChecksum(WinDivertBuffer buf)
        {
            buf[10] = 0;
            buf[11] = 0;
            ushort checksum = ComputeChecksum(buf, 0, (buf[0] & 0x0F) * 4);
            buf[10] = (byte)(checksum >> 8);
            buf[11] = (byte)(checksum & 0xFF);
        }

        void FixTCPChecksum(WinDivertBuffer buf, int ipHeaderLen, int packetLen)
        {
            int tcpLen = packetLen - ipHeaderLen;

            buf[ipHeaderLen + 16] = 0;
            buf[ipHeaderLen + 17] = 0;

            uint sum = 0;
            for (int i = 12; i < 20; i += 2)
                sum += (uint)((buf[i] << 8) + buf[i + 1]);

            sum += 6;
            sum += (uint)tcpLen;

            sum += ChecksumSum(buf, ipHeaderLen, tcpLen);

            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);

            ushort checksum = (ushort)~sum;
            buf[ipHeaderLen + 16] = (byte)(checksum >> 8);
            buf[ipHeaderLen + 17] = (byte)(checksum & 0xFF);
        }

        ushort ComputeChecksum(WinDivertBuffer buf, int start, int length)
        {
            uint sum = ChecksumSum(buf, start, length);
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        uint ChecksumSum(WinDivertBuffer buf, int start, int length)
        {
            uint sum = 0;
            for (int i = start; i < start + length; i += 2)
            {
                ushort word = (ushort)((buf[i] << 8) + ((i + 1 < buf.Length) ? buf[i + 1] : 0));
                sum += word;
            }
            return sum;
        }

        public void WinDivertThread()
        {
            var handle = WinDivert.WinDivertOpen(
                "udp and inbound",             // capture all inbound UDP packets
                WinDivertLayer.Network,        // work at network layer
                0,                             // priority
                0                              // flags
            );
            if (handle == IntPtr.Zero)
            {
                Debug.WriteLine("Failed to open WinDivert handle.");
                return;
            }

            WinDivertBuffer buffer = new WinDivertBuffer();
            WinDivertAddress addr = new WinDivertAddress();

            while (true)
            {
                if (!WinDivert.WinDivertRecv(handle, buffer, ref addr, ref packetLen))
                    continue;

                byte ipHeaderLen = (byte)((buffer[0] & 0x0F) * 4);
                byte protocol = buffer[9];

                byte src1 = buffer[12];
                byte src2 = buffer[13];
                byte src3 = buffer[14];
                byte src4 = buffer[15];

                byte dst1 = buffer[16];
                byte dst2 = buffer[17];
                byte dst3 = buffer[18];
                byte dst4 = buffer[19];

                string srcIP = $"{src1}.{src2}.{src3}.{src4}";
                string dstIP = $"{dst1}.{dst2}.{dst3}.{dst4}";

                bool isrbx = isRoblox(srcIP);
                if (started && isrbx)
                {
                    string[] ftr = "82 284 85 1185 1162 1158 79 101 216 264".Split(" ");
                    List<uint> ftr2 = new List<uint>();
                    foreach (string l in ftr)
                    {
                        ftr2.Add(uint.Parse(l));
                    }
                    if (!ftr2.Contains(packetLen))
                    {
                        Debug.WriteLine($"denied {packetLen} ({srcIP})");

                        byte tcpHeaderLen = (byte)((buffer[ipHeaderLen + 12] >> 4) * 4);

                        int payloadOffset = ipHeaderLen + tcpHeaderLen;
                        int payloadLength = (int)(packetLen - payloadOffset);

                        for (int i = payloadOffset; i < packetLen; i++)
                        {
                            buffer[i] = (byte)0;
                        }

                        FixIPChecksum(buffer);
                        FixTCPChecksum(buffer, ipHeaderLen, (int)packetLen);
                    } else
                    {
                        Debug.WriteLine("accepted " + packetLen);
                    }
                }

                WinDivert.WinDivertSend(handle, buffer, packetLen, ref addr);
            }
        }
        public void WinDivertThread2()
        {
            var handle = WinDivert.WinDivertOpen(
                "udp and outbound",            // capture all outbound UDP packets
                WinDivertLayer.Network,        // work at network layer
                0,                             // priority
                0                              // flags
            );
            if (handle == IntPtr.Zero)
            {
                Debug.WriteLine("Failed to open WinDivert handle.");
                return;
            }

            WinDivertBuffer buffer = new WinDivertBuffer();
            WinDivertAddress addr = new WinDivertAddress();

            while (true)
            {
                if (!WinDivert.WinDivertRecv(handle, buffer, ref addr, ref packetLen))
                    continue;

                byte ipHeaderLen = (byte)((buffer[0] & 0x0F) * 4);
                byte protocol = buffer[9];

                byte src1 = buffer[12];
                byte src2 = buffer[13];
                byte src3 = buffer[14];
                byte src4 = buffer[15];

                byte dst1 = buffer[16];
                byte dst2 = buffer[17];
                byte dst3 = buffer[18];
                byte dst4 = buffer[19];

                string srcIP = $"{src1}.{src2}.{src3}.{src4}";
                string dstIP = $"{dst1}.{dst2}.{dst3}.{dst4}";

                bool isrbx = isRoblox(dstIP);
                if (started && isrbx)
                {
                    string[] ftr = "93 1158 232 87 109 1158 280 176 105 278 236 304 84 1162 1052 1162 1122 517 197 874 892 741 822 1120 1133 1151 1134 477 1165 1146".Split(" ");
                    List<uint> ftr2 = new List<uint>();
                    foreach (string l in ftr)
                    {
                        ftr2.Add(uint.Parse(l));
                    }
                    if (!ftr2.Contains(packetLen) && packetLen < 490)
                    {
                        Debug.WriteLine($"denied2 {packetLen} ({dstIP})");

                        byte tcpHeaderLen = (byte)((buffer[ipHeaderLen + 12] >> 4) * 4);

                        int payloadOffset = ipHeaderLen + tcpHeaderLen;
                        int payloadLength = (int)(packetLen - payloadOffset);

                        for (int i = payloadOffset; i < packetLen; i++)
                        {
                            buffer[i] = (byte)0;
                        }

                        FixIPChecksum(buffer);
                        FixTCPChecksum(buffer, ipHeaderLen, (int)packetLen);
                    }
                    else
                    {
                        Debug.WriteLine("accepted2 " + packetLen);
                    }
                }

                WinDivert.WinDivertSend(handle, buffer, packetLen, ref addr);
            }
        }
        public MainWindow()
        {
            InitializeComponent();
            {
                Thread t = new Thread(WinDivertThread); // recv
                t.IsBackground = true;
                t.Start();
            }
            {
                Thread t = new Thread(WinDivertThread2); // snd
                t.IsBackground = true;
                t.Start();
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            started = true;
            StateText.Text = "State: ON";
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            started = false;
            StateText.Text = "State: OFF";
        }
    }
}
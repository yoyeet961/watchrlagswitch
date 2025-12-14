using System.Diagnostics;
using System.IO;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using WinDivertSharp;

namespace watchrlagswitch
{
    public class GetKeyPressed
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        private static IntPtr _hook;
        private static LowLevelKeyboardProc _proc = HookCallback;

        public static event Action<Key> KeyCaptured;

        public static void Start()
        {
            if (_hook != IntPtr.Zero)
                return;

            using Process p = Process.GetCurrentProcess();
            using ProcessModule m = p.MainModule;

            _hook = SetWindowsHookEx(
                WH_KEYBOARD_LL,
                _proc,
                GetModuleHandle(m.ModuleName),
                0
            );
        }

        public static void Stop()
        {
            if (_hook == IntPtr.Zero)
                return;

            UnhookWindowsHookEx(_hook);
            _hook = IntPtr.Zero;
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 &&
               (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vk = Marshal.ReadInt32(lParam);

                Key key = KeyInterop.KeyFromVirtualKey(vk);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    KeyCaptured?.Invoke(key);
                });

                Stop();
                return (IntPtr)1;
            }

            return CallNextHookEx(_hook, nCode, wParam, lParam);
        }

        private delegate IntPtr LowLevelKeyboardProc(
            int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(
            int idHook, LowLevelKeyboardProc lpfn,
            IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(
            IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string name);
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const int WM_HOTKEY = 0x0312;
        private const uint MOD_ALT = 0x0001;
        private const uint MOD_CONTROL = 0x0002;
        private const uint MOD_SHIFT = 0x0004;
        private const uint MOD_WIN = 0x0008;
        private const int HOTKEY_ID = 0x6741; // Yoo this hotkey id so Tuff 🔥🔥
        public uint packetLen;
        public bool started = false;
        public bool blocksent = true;
        public bool blockrecv = true;
        Dictionary<string, bool> robloxfilter = new Dictionary<string, bool>();
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool RegisterHotKey(
            IntPtr hWnd,
            int id,
            uint fsModifiers,
            uint vk
        );
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnregisterHotKey(
            IntPtr hWnd,
            int id
        );
        private HwndSource _source;

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
                if (started && isrbx && blockrecv)
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
                if (started && isrbx && blocksent)
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

            this.Loaded += MainWindow_Loaded;
            this.Closed += MainWindow_Closed;
        }
        int hotkey = KeyInterop.VirtualKeyFromKey(Key.F7);

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            IntPtr handle = new WindowInteropHelper(this).Handle;
            _source = HwndSource.FromHwnd(handle);
            _source.AddHook(WndProc);

            if (File.Exists("hotkey.txt"))
            {
                hotkey = int.Parse(File.ReadAllText("hotkey.txt"));
            } else
            {
                File.WriteAllText("hotkey.txt", hotkey.ToString());
            }
            HotkeyBox.Text = KeyInterop.KeyFromVirtualKey(hotkey).ToString();

            bool success = RegisterHotKey(
                handle,
                HOTKEY_ID,
                0,
                (uint)hotkey
            );
            if (!success)
            {
                MessageBox.Show("Error registering hotkey", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void MainWindow_Closed(object sender, EventArgs e)
        {
            IntPtr handle = new WindowInteropHelper(this).Handle;
            UnregisterHotKey(handle, HOTKEY_ID);
            _source?.RemoveHook(WndProc);
        }

        private IntPtr WndProc(
            IntPtr hwnd,
            int msg,
            IntPtr wParam,
            IntPtr lParam,
            ref bool handled)
        {
            if (msg == WM_HOTKEY && wParam.ToInt32() == HOTKEY_ID)
            {
                OnHotkeyPressed();
                handled = true;
            }

            return IntPtr.Zero;
        }

        private void OnHotkeyPressed()
        {
            Dispatcher.Invoke(() =>
            {
                Debug.WriteLine("hotkey");
                started = !started;
                if (StateText.Text == "State: ON")
                {
                    StateText.Text = "State: OFF";
                }
                else
                {
                    StateText.Text = "State: ON";
                }
            });
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

        private void HotkeyBox_MouseDown(object sender, MouseButtonEventArgs e)
        {
            HotkeyBox.Text = "...";
            GetKeyPressed.Start();
            GetKeyPressed.KeyCaptured += GetKeyPressed_KeyCaptured;
        }

        private void GetKeyPressed_KeyCaptured(Key obj)
        {
            IntPtr handle = new WindowInteropHelper(this).Handle;
            HotkeyBox.Text = obj.ToString();
            UnregisterHotKey(handle, HOTKEY_ID);
            bool success = RegisterHotKey(
                handle,
                HOTKEY_ID,
                0,
                (uint)KeyInterop.VirtualKeyFromKey(obj)
            );
            if (!success)
            {
                MessageBox.Show("Error registering hotkey", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            File.WriteAllText("hotkey.txt", KeyInterop.VirtualKeyFromKey(obj).ToString());
        }

        private void RecvCB_Checked(object sender, RoutedEventArgs e)
        {
            blockrecv = true;
        }

        private void RecvCB_Unchecked(object sender, RoutedEventArgs e)
        {
            blockrecv = false;
        }

        private void SendCB_Checked(object sender, RoutedEventArgs e)
        {
            blocksent = true;
        }

        private void SendCB_Unchecked(object sender, RoutedEventArgs e)
        {
            blocksent = false;
        }
    }
}
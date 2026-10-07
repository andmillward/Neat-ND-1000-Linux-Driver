# Converts a USBPcap capture of the ND-1000 into a JSON-lines trace of every operation:
#   co = control OUT (setup + data)     ci = control IN (setup + returned data)
#   bo = bulk OUT (full data)           bi = bulk IN (length only; image data is not stored)
# Also writes a compact, run-length-compressed text view for reading.
param([Parameter(Mandatory)][string]$Pcap, [Parameter(Mandatory)][string]$Out, [int]$Device = -1,
      [double]$From = 0, [double]$To = 1e9)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public static class NeatTrace {
    class Pending { public double T; public int Rt, Rq, V, I, N; }
    public static string Run(string pcap, string outPath, int device, double from, double to) {
        var ops = new List<string>();
        var view = new List<string>();
        var pend = new Dictionary<ulong, Pending>();
        using (var br = new BinaryReader(File.OpenRead(pcap))) {
            if (br.ReadUInt32() != 0xa1b2c3d4) throw new Exception("need classic little-endian pcap");
            br.ReadBytes(20);
            double t0 = -1;
            while (br.BaseStream.Position < br.BaseStream.Length) {
                uint sec = br.ReadUInt32(), usec = br.ReadUInt32(), incl = br.ReadUInt32(); br.ReadUInt32();
                byte[] r = br.ReadBytes((int)incl);
                double t = sec + usec / 1e6; if (t0 < 0) t0 = t; t -= t0;
                int hlen = BitConverter.ToUInt16(r, 0);
                if (device >= 0 && BitConverter.ToUInt16(r, 19) != device) continue;
                if (t < from || t > to) continue;
                ulong irp = BitConverter.ToUInt64(r, 2);
                bool fromDev = (r[16] & 1) == 1;
                byte ep = r[21], xfer = r[22];
                int dlen = (int)BitConverter.ToUInt32(r, 23), avail = Math.Min(dlen, r.Length - hlen);
                if (xfer == 2 && !fromDev && hlen >= 28 && r.Length >= hlen + 8) {
                    int s = hlen, rt = r[s], rq = r[s + 1];
                    int v = r[s + 2] | (r[s + 3] << 8), i = r[s + 4] | (r[s + 5] << 8), n = r[s + 6] | (r[s + 7] << 8);
                    if ((rt & 0x80) == 0) {
                        string d = Hex(r, s + 8, r.Length - s - 8);
                        ops.Add(string.Format("{{\"t\":{0:F4},\"op\":\"co\",\"rt\":{1},\"rq\":{2},\"v\":{3},\"i\":{4},\"d\":\"{5}\"}}", t, rt, rq, v, i, d));
                        view.Add(string.Format("co {0:X2} {1,2} v={2:X4} i={3:X4} {4}", rt, rq, v, i, d.Length > 48 ? d.Substring(0, 48) + "..(" + d.Length / 2 + ")" : d));
                    } else pend[irp] = new Pending { T = t, Rt = rt, Rq = rq, V = v, I = i, N = n };
                } else if (xfer == 2 && fromDev && pend.ContainsKey(irp)) {
                    var p = pend[irp]; pend.Remove(irp);
                    string d = Hex(r, hlen, avail);
                    ops.Add(string.Format("{{\"t\":{0:F4},\"op\":\"ci\",\"rt\":{1},\"rq\":{2},\"v\":{3},\"i\":{4},\"n\":{5},\"r\":\"{6}\"}}", p.T, p.Rt, p.Rq, p.V, p.I, p.N, d));
                    view.Add(string.Format("ci {0:X2} {1,2} v={2:X4} i={3:X4} n={4} -> {5}", p.Rt, p.Rq, p.V, p.I, p.N, d.Length > 48 ? d.Substring(0, 48) + ".." : d));
                } else if (xfer == 3 && !fromDev && ep == 0x02 && avail > 0) {
                    ops.Add(string.Format("{{\"t\":{0:F4},\"op\":\"bo\",\"ep\":2,\"d\":\"{1}\"}}", t, Hex(r, hlen, avail)));
                    view.Add(string.Format("bo {0} bytes", avail));
                } else if (xfer == 3 && fromDev && ep == 0x81 && dlen > 0) {
                    ops.Add(string.Format("{{\"t\":{0:F4},\"op\":\"bi\",\"ep\":129,\"n\":{1}}}", t, dlen));
                    view.Add(string.Format("bi {0} bytes", dlen));
                }
            }
        }
        File.WriteAllLines(outPath, ops);
        // run-length compress the view: identical consecutive lines become "xN"
        var sb = new StringBuilder(); string prev = null; int cnt = 0;
        Action flush = () => { if (prev != null) sb.AppendLine(cnt > 1 ? prev + "   x" + cnt : prev); };
        foreach (var l in view) { if (l == prev) cnt++; else { flush(); prev = l; cnt = 1; } }
        flush();
        File.WriteAllText(Path.ChangeExtension(outPath, ".view.txt"), sb.ToString());
        return string.Format("{0} operations -> {1}", ops.Count, outPath);
    }
    static string Hex(byte[] b, int o, int n) {
        var sb = new StringBuilder(n * 2);
        for (int k = 0; k < n && o + k < b.Length; k++) sb.Append(b[o + k].ToString("x2"));
        return sb.ToString();
    }
}
'@
[NeatTrace]::Run((Resolve-Path $Pcap).Path, $Out, $Device, $From, $To)

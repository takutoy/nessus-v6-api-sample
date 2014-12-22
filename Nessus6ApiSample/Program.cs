using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nessus6ApiSample
{
    class Program
    {
        static void Main(string[] args)
        {
            NessusTestAsync().Wait();
        }

        static async Task NessusTestAsync()
        {
            // Ignore SSL validation
            System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            string scanname = "test_" + DateTime.Now.ToString("yyyyMMddHHmmss");

            var nessus = new Nessus6Api("192.168.248.129");
            var token = await nessus.LoginAsync("admin", "password");

            var policies = await nessus.GetPolicyTemplatesAsync();
            var basic_network_scan_uuid = policies["Basic Network Scan"];

            var scan_id = await nessus.CreateScanAsync(scanname, basic_network_scan_uuid, "127.0.0.1");
            var scan_uuid = await nessus.LaunchScanAsync(scan_id);

            var history_ids = await nessus.GetScanHistories(scan_id);
            var history_id = history_ids[scan_uuid];

            while (true)
            {
                var status = await nessus.GetScanStatus(scan_id, history_id);
                if (status != "running") break;
                await Task.Delay(1000 * 10);
            }

            var fid = await nessus.ExportScanAsync(scan_id, history_id, "nessus");
            var download = await nessus.DownloadScanAsync(scan_id, fid);
            File.WriteAllBytes(scanname + ".nessus", download);

            var fidhtml = await nessus.ExportScanAsync(scan_id, history_id, "html");
            var downloadhtml = await nessus.DownloadScanAsync(scan_id, fidhtml);
            File.WriteAllBytes(scanname + ".html", downloadhtml);

            await nessus.DeleteScan(scan_id);

            await nessus.LogoutAsync();
        }

    }
}

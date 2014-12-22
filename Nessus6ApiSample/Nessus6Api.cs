using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Nessus6ApiSample
{
    public class Nessus6Api
    {
        string nessusip = null;
        string token = null;

        public Nessus6Api(string ipaddress)
        {
            nessusip = ipaddress;
        }

        async Task<JObject> ConnectAsync(string method, string resource, JObject param = null)
        {
            Uri uri = new Uri(string.Format("https://{0}:8834{1}", nessusip, resource));

            using (HttpClient hc = new HttpClient())
            {
                if (token != null)
                {
                    hc.DefaultRequestHeaders.Add("X-Cookie", string.Format("token={0}", token));
                }

                switch (method.ToUpper())
                {
                    default:
                        throw new ArgumentException();
                    case "GET":
                        var getjson = await hc.GetStringAsync(uri);
                        return (JObject)JsonConvert.DeserializeObject(getjson);
                    case "POST":
                        HttpContent postcontent;
                        if (param == null) postcontent = new StringContent("");
                        else postcontent = new StringContent(param.ToString(), Encoding.UTF8, "application/json");
                        var postresponse = await hc.PostAsync(uri, postcontent);
                        var postrjson = (JObject)JsonConvert.DeserializeObject(await postresponse.Content.ReadAsStringAsync());
                        return postrjson;
                    case "PUT":
                        var putresponse = await hc.PostAsync(uri, new StringContent(param.ToString(), Encoding.UTF8, "application/json"));
                        var putjson = (JObject)JsonConvert.DeserializeObject(await putresponse.Content.ReadAsStringAsync());
                        return putjson;
                    case "DELETE":
                        var deleteresponse = await hc.DeleteAsync(uri);
                        var deletejson = (JObject)JsonConvert.DeserializeObject(await deleteresponse.Content.ReadAsStringAsync());
                        return deletejson;
                }
            }
        }

        public async Task<string> LoginAsync(string login, string password)
        {
            JObject param = new JObject(
                new JProperty("username", login),
                new JProperty("password", password)
                );
            var json = await ConnectAsync("POST", "/session", param);

            this.token = (string)json["token"];
            return token;
        }

        public async Task LogoutAsync()
        {
            var response = await ConnectAsync("DELETE", "/session");
            return;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <returns>dictionary of policy title and uuid</returns>
        public async Task<Dictionary<string, string>> GetPolicyTemplatesAsync()
        {
            var response = await ConnectAsync("GET", "/editor/policy/templates");
            var data = response.SelectToken("templates").ToDictionary(_ => (string)_["title"], _ => (string)_["uuid"]);
            return data;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="name"></param>
        /// <param name="policyId"></param>
        /// <param name="targets"></param>
        /// <param name="description"></param>
        /// <returns>scan id</returns>
        public async Task<int> CreateScanAsync(string name, string policyId, string targets, string description = "")
        {
            JObject param = new JObject(
                new JProperty("uuid", policyId),
                new JProperty("settings", new JObject(
                    new JProperty("name", name),
                    new JProperty("description", description),
                    new JProperty("text_targets", targets))));

            var response = await ConnectAsync("POST", "/scans", param);

            return (int)response["scan"]["id"];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scan_id"></param>
        /// <returns>scan uuid</returns>
        public async Task<string> LaunchScanAsync(int scan_id)
        {
            string resource = string.Format("/scans/{0}/launch", scan_id);
            var response = await ConnectAsync("POST", resource);
            return (string)response["scan_uuid"];
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="scan_id"></param>
        /// <returns>dictionary of scan uuid and history id</returns>
        public async Task<Dictionary<string, int>> GetScanHistoriesAsync(int scan_id)
        {
            string resource = string.Format("/scans/{0}", scan_id);
            var response = await ConnectAsync("GET", resource);
            var data = response.SelectToken("history").ToDictionary(_ => (string)_["uuid"], _ => (int)_["history_id"]);
            return data;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scan_id"></param>
        /// <returns>scan status string</returns>
        public async Task<string> GetScanStatusAsync(int scan_id, int history_id)
        {
            string resource = string.Format("/scans/{0}?history_id={1}", scan_id, history_id);
            var response = await ConnectAsync("GET", resource);
            var data = (string)response["info"]["status"];
            return data;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scan_id"></param>
        /// <param name="history_id"></param>
        /// <param name="format"></param>
        /// <returns>file id</returns>
        public async Task<int> ExportScanAsync(int scan_id, int history_id = -1, string format = "nessus")
        {
            JObject param = new JObject(
                new JProperty("format", format),
                new JProperty("chapters", "vuln_hosts_summary")
                );
            if (history_id != -1)
            {
                param["history_id"] = history_id;
            }

            var response = await ConnectAsync("POST", string.Format("/scans/{0}/export", scan_id), param);
            var fid = (int)response["file"];

            while (true)
            {
                var statusresponse = await ConnectAsync("GET", string.Format("/scans/{0}/export/{1}/status", scan_id, fid));
                if ((string)statusresponse["status"] != "loading") break;
                await Task.Delay(1000);
            }

            return fid;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scan_id"></param>
        /// <param name="fileId"></param>
        /// <returns>content of export file</returns>
        public async Task<byte[]> DownloadScanAsync(int scan_id, int fileId)
        {
            using (HttpClient hc = new HttpClient())
            {
                hc.DefaultRequestHeaders.Add("X-Cookie", string.Format("token={0}", token));
                Uri uri = new Uri(string.Format("https://{0}:8834/scans/{1}/export/{2}/download", nessusip, scan_id, fileId));
                var response = await hc.GetByteArrayAsync(uri);
                return response;
            }
        }

        /// <summary>
        /// delete a scan or history if hid is specified
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="hid"></param>
        /// <returns></returns>
        public async Task DeleteScanAsync(int scan_id, int history_id = -1)
        {
            string resource = history_id == -1 ?
                string.Format("/scans/{0}", scan_id) :
                string.Format("/scans/{0}/history/{1}", scan_id, history_id);

            var response = await ConnectAsync("DELETE", resource);
            return;
        }
    }
}

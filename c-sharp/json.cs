using System;
using System.IO;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using Newtonsoft.Json;

namespace JSONReader
{
    class Program
    {
        static void Main(string[] args)
        {
            int contentPrefix = Array.IndexOf(args, "--content");
            string content = args[contentPrefix+1];

            JavaScriptSerializer s = new JavaScriptSerializer();
            System.Console.WriteLine(content);
            IDictionary<string, object> result = s.Deserialize<IDictionary<string, object>>(content);
            System.Console.WriteLine(result["status"]);

            return;
        }
    }
}

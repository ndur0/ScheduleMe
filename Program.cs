using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.IO;
using System.Security.Principal;
using System.Linq.Expressions;
using NDesk.Options;

namespace ScheduleMe
{
    public class Program
    {
        private static bool _findWritable;
        private static bool _shutdowRestart;
        private static int _time2Restart;
        public static void Main(string[] args)
        {
            var help = false;
         
            OptionSet options = new OptionSet()
            {
                {"f|findWriteable","Task ScheduleMe to find writeable folders in user path to drop crafted dll", v => _findWritable = v != null},
                {"s|shutdownRestart","Option to restart computer AFTER crafted dll is dropped. Default: 30 seconds otherwise use -t <sec>", v => _shutdowRestart = v !=null},
                {"t=|time2restart","Optional: time to wait before shutdown. Default: 30 seconds", (int v) => _time2Restart = v},
                {"h|?|help","Show Help", v => help = v != null},
            };

            try
            {
                options.Parse(args);

                if (args.Length == 0)
                {
                    Console.WriteLine("Please enter an option");
                    Help(options);
                    return;
                }
                if (help)
                {
                    Help(options);
                    return;
                }
                else if (_findWritable)
                {
                    Console.WriteLine("\nFinding writeable folders in users %path%\n");
                    EnvironmentVariable();
                    return;
                }
                else if (_shutdowRestart)
                {
                    Console.WriteLine("Restarting computer AFTER crafted dll is dropped. Default: 30 seconds");
                    Process.Start("shutdown", "/r /t 30");
                    return;
                }
                //Windows message will show restart in 1 min, even though chose ie: 90, 180 etc
                else if (_time2Restart != 0)
                {
                    Console.WriteLine("Restarting computer in " + _time2Restart);
                    Process.Start("shutdown", "/r /t " + _time2Restart);
                    return;
                }

            }
            
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
                Help(options);
                return;
            }
                        
        }

        public static void Help(OptionSet p)
        {
            Console.WriteLine("Usage:");
            p.WriteOptionDescriptions(Console.Out);
        }

        public static string EnvironmentVariable()
        {
            string pathEnvVar = Environment.GetEnvironmentVariable("PATH");
            string[] envPaths = pathEnvVar.Split(new char[1] { Path.PathSeparator });
            foreach (string envPath in envPaths)
            {
                try 
                {
                    bool writeable = CheckDirectoryWritePermissions(envPath, FileSystemRights.Write);
                    if (writeable)
                    {
                        Console.WriteLine($"Directory Write Permission: {envPath}\n");
                    }
                    
                }                  
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine("Check Access: {0}\n", envPath);
                }
                catch (System.ArgumentException e)
                {
                   Console.WriteLine("Invalid name or empty path found - - - - > ignoring\n");
                }
                catch (System.InvalidOperationException e)
                {
                    Console.WriteLine("Path doesnt exist: {0}\n", envPath);
                }
            }

            return null;
        }

        public static bool CheckDirectoryWritePermissions(string path, FileSystemRights accessRights)
        {
            var isInRoleWithAccess = false;

            try
            {
                var di = new DirectoryInfo(path);
                var acl = di.GetAccessControl();
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                var currentUser = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(currentUser);
                foreach (AuthorizationRule rule in rules)
                {
                    var fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & accessRights) > 0)
                    {
                        var ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                            continue;

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            if (fsAccessRule.AccessControlType == AccessControlType.Deny)
                                return false;
                            isInRoleWithAccess = true;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            return isInRoleWithAccess;
        }
                
    }
}

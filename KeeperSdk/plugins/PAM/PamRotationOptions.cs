using System;
using System.Collections.Generic;

namespace KeeperSecurity.Plugins.PAM
{
    /// <summary>
    /// Options for PAM record rotation configuration commands.
    /// Shared by Commander and PowerCommander.
    /// </summary>
    public class PamRotationOptions
    {
        public static readonly HashSet<string> ScriptVerbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "list", "l", "add", "new", "n", "a", "edit", "e", "delete", "d",
        };

        public string Command { get; set; }

        public string ScriptSubCommand { get; set; }

        public string ScriptArgument { get; set; }

        public bool Force { get; set; }

        public string Record { get; set; }

        public string RecordUid { get; set; }

        public string Folder { get; set; }

        public string Config { get; set; }

        public string IamAadConfig { get; set; }

        public string RotationProfile { get; set; }

        public string SaasConfigUid { get; set; }

        public string Resource { get; set; }

        public string ScheduleJson { get; set; }

        public string ScheduleCron { get; set; }

        public bool OnDemand { get; set; }

        public bool ScheduleConfig { get; set; }

        public bool ScheduleOnly { get; set; }

        public string Complexity { get; set; }

        public string ComplexityJson { get; set; }

        public string AdminUser { get; set; }

        public bool Enable { get; set; }

        public bool Disable { get; set; }

        public bool Verbose { get; set; }

        public string Format { get; set; }

        public string ScriptCommand { get; set; }

        public string Script { get; set; }

        public string RunCommand { get; set; }

        public IEnumerable<string> AddCredential { get; set; }

        public IEnumerable<string> RemoveCredential { get; set; }

        public string Pattern { get; set; }

        public string EffectiveRecord => !string.IsNullOrWhiteSpace(Record) ? Record : RecordUid;

        public string EffectiveRunCommand
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(RunCommand))
                {
                    return RunCommand;
                }

                if (!string.IsNullOrWhiteSpace(ScriptCommand)
                    && !ScriptVerbs.Contains(ScriptCommand.Trim()))
                {
                    return ScriptCommand.Trim();
                }

                return null;
            }
        }
    }
}

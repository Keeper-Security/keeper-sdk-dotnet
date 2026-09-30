using System;
using System.Collections.Generic;
using Cli;

namespace Commander
{
    internal static class NsfCommandRegistration
    {
        internal static void AppendNsfCommands(this VaultContext context, CliCommands cli)
        {
            cli.Commands.Add("nsf-list",
                new ParseableCommand<NsfListOptions>
                {
                    Order = 45,
                    Description = "List Keeper NSF folders and records",
                    Action = context.NsfListCommand
                });

            cli.Commands.Add("nsf-folders",
                new ParseableCommand<NsfFoldersOptions>
                {
                    Order = 45,
                    Description = "List Keeper NSF folders",
                    Action = context.NsfFoldersCommand
                });

            cli.Commands.Add("nsf-records",
                new ParseableCommand<NsfRecordsOptions>
                {
                    Order = 45,
                    Description = "List Keeper NSF records",
                    Action = context.NsfRecordsCommand
                });

            cli.Commands.Add("nsf-get",
                new ParseableCommand<NsfGetOptions>
                {
                    Order = 45,
                    Description = "Get detailed Keeper NSF record or folder information",
                    Action = context.NsfGetCommand
                });

            cli.Commands.Add("nsf-record-details",
                new ParseableCommand<NsfRecordDetailsOptions>
                {
                    Order = 45,
                    Description = "Get Keeper NSF record metadata",
                    Action = context.NsfRecordDetailsCommand
                });

            cli.Commands.Add("nsf-mkdir",
                new ParseableCommand<NsfMkdirOptions>
                {
                    Order = 46,
                    Description = "Create a Keeper NSF folder",
                    Action = context.NsfMkdirCommand
                });

            cli.Commands.Add("nsf-rndir",
                new ValidatingParseableCommand<NsfRndirOptions>
                {
                    Order = 46,
                    Description = "Rename or recolor a Keeper NSF folder",
                    Validate = tokens => ValidateOptionValue(
                        tokens,
                        "--name",
                        "-n",
                        "Folder name cannot be empty.",
                        "--color",
                        "--no-inherit"),
                    Action = context.NsfRndirCommand
                });

            cli.Commands.Add("nsf-rmdir",
                new ParseableCommand<NsfRmdirOptions>
                {
                    Order = 46,
                    Description = "Remove Keeper NSF folder(s)",
                    Action = context.NsfRmdirCommand
                });

            cli.Commands.Add("nsf-move",
                new ParseableCommand<NsfMoveOptions>
                {
                    Order = 46,
                    Description = "Move a Keeper NSF record or folder to a new folder",
                    Action = context.NsfMoveCommand
                });

            cli.Commands.Add("nsf-share-folder",
                new ParseableCommand<NsfShareFolderOptions>
                {
                    Order = 46,
                    Description = "Grant or revoke Keeper NSF folder access",
                    Action = context.NsfShareFolderCommand
                });

            cli.Commands.Add("nsf-record-add",
                new ParseableCommand<NsfRecordAddOptions>
                {
                    Order = 47,
                    Description = "Create a Keeper NSF record",
                    Action = context.NsfRecordAddCommand
                });

            cli.Commands.Add("nsf-record-update",
                new ValidatingParseableCommand<NsfRecordUpdateOptions>
                {
                    Order = 47,
                    Description = "Update a Keeper NSF record",
                    Validate = tokens => ValidateOptionValue(
                        tokens,
                        "--title",
                        null,
                        "Record title cannot be empty.",
                        "--type",
                        "-t",
                        "--notes",
                        "--generate",
                        "-g"),
                    Action = context.NsfRecordUpdateCommand
                });

            cli.Commands.Add("nsf-share-record",
                new ParseableCommand<NsfShareRecordOptions>
                {
                    Order = 47,
                    Description = "Grant or revoke Keeper NSF record access",
                    Action = context.NsfShareRecordCommand
                });

            cli.Commands.Add("nsf-record-permission",
                new ParseableCommand<NsfRecordPermissionOptions>
                {
                    Order = 47,
                    Description = "Bulk grant or revoke record permissions in a Keeper NSF folder",
                    Action = context.NsfRecordPermissionCommand
                });

            cli.Commands.Add("nsf-shortcut-list",
                new ParseableCommand<NsfShortcutListOptions>
                {
                    Order = 47,
                    Description = "List Keeper NSF shortcut records",
                    Action = context.NsfShortcutListCommand
                });

            cli.Commands.Add("nsf-shortcut-keep",
                new ParseableCommand<NsfShortcutKeepOptions>
                {
                    Order = 47,
                    Description = "Keep a Keeper NSF record in one folder only",
                    Action = context.NsfShortcutKeepCommand
                });

            cli.Commands.Add("nsf-rm",
                new ParseableCommand<NsfRmOptions>
                {
                    Order = 47,
                    Description = "Remove Keeper NSF record(s)",
                    Action = context.NsfRmCommand
                });

            cli.Commands.Add("nsf-ln",
                new ParseableCommand<NsfLnOptions>
                {
                    Order = 47,
                    Description = "Link a Keeper NSF record into a folder",
                    Action = context.NsfLnCommand
                });

            cli.Commands.Add("nsf-transfer-record",
                new ParseableCommand<NsfTransferRecordOptions>
                {
                    Order = 47,
                    Description = "Transfer Keeper NSF record ownership",
                    Action = context.NsfTransferRecordCommand
                });
        }

        private static string ValidateOptionValue(
            IReadOnlyList<string> tokens,
            string longOption,
            string shortOption,
            string errorMessage,
            params string[] recognizedOptions)
        {
            for (var i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];
                var hasOption = string.Equals(token, longOption, StringComparison.Ordinal)
                    || (!string.IsNullOrEmpty(shortOption)
                        && string.Equals(token, shortOption, StringComparison.Ordinal));

                if (hasOption)
                {
                    if (i + 1 >= tokens.Count
                        || IsRecognizedOption(tokens[i + 1], recognizedOptions)
                        || string.IsNullOrWhiteSpace(tokens[i + 1]))
                    {
                        return errorMessage;
                    }
                }
                else if ((token.StartsWith(longOption + "=", StringComparison.Ordinal)
                        || (!string.IsNullOrEmpty(shortOption)
                            && token.StartsWith(shortOption + "=", StringComparison.Ordinal)))
                    && string.IsNullOrWhiteSpace(token.Substring(token.IndexOf('=') + 1)))
                {
                    return errorMessage;
                }
            }

            return null;
        }

        private static bool IsRecognizedOption(string token, string[] recognizedOptions)
        {
            foreach (var option in recognizedOptions)
            {
                if (string.Equals(token, option, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}

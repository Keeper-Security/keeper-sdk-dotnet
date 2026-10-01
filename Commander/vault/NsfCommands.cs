using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Cli;
using CommandLine;

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
                    Validate = tokens => ThrowOnValidationError(ValidateOptionValue<NsfRndirOptions>(
                        tokens,
                        "--name",
                        "-n",
                        "Folder name cannot be empty.")),
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
                    Validate = tokens => ThrowOnValidationError(ValidateOptionValue<NsfRecordUpdateOptions>(
                        tokens,
                        "--title",
                        null,
                        "Record title cannot be empty.")),
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

        private static string ValidateOptionValue<TOptions>(
            IReadOnlyList<string> tokens,
            string longOption,
            string shortOption,
            string errorMessage)
        {
            var optionNames = GetOptionNames<TOptions>();
            for (var i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];
                var hasOption = string.Equals(token, longOption, StringComparison.OrdinalIgnoreCase)
                    || (!string.IsNullOrEmpty(shortOption)
                        && string.Equals(token, shortOption, StringComparison.OrdinalIgnoreCase));

                if (hasOption)
                {
                    if (i + 1 >= tokens.Count
                        || IsRecognizedOption(tokens[i + 1], optionNames)
                        || string.IsNullOrWhiteSpace(tokens[i + 1]))
                    {
                        return errorMessage;
                    }
                }
                else if ((token.StartsWith(longOption + "=", StringComparison.OrdinalIgnoreCase)
                        || (!string.IsNullOrEmpty(shortOption)
                            && token.StartsWith(shortOption + "=", StringComparison.OrdinalIgnoreCase)))
                    && string.IsNullOrWhiteSpace(token.Substring(token.IndexOf('=') + 1)))
                {
                    return errorMessage;
                }
            }

            return null;
        }

        private static string ThrowOnValidationError(string validationError)
        {
            if (!string.IsNullOrEmpty(validationError))
            {
                throw new CommandError(validationError);
            }

            return null;
        }

        private static HashSet<string> GetOptionNames<TOptions>()
        {
            return new HashSet<string>(
                typeof(TOptions).GetProperties()
                    .Select(property => property.GetCustomAttribute<OptionAttribute>())
                    .Where(option => option != null)
                    .SelectMany(option => new[]
                    {
                        string.IsNullOrEmpty(option.LongName) ? null : "--" + option.LongName,
                        string.IsNullOrEmpty(option.ShortName) ? null : "-" + option.ShortName
                    })
                    .Where(option => option != null),
                StringComparer.OrdinalIgnoreCase);
        }

        private static bool IsRecognizedOption(string token, ISet<string> recognizedOptions)
        {
            var equalsIndex = token.IndexOf('=');
            var optionName = equalsIndex >= 0 ? token.Substring(0, equalsIndex) : token;
            return recognizedOptions.Contains(optionName);
        }
    }
}

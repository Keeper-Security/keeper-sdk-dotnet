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
                new ParseableCommand<NsfRndirOptions>
                {
                    Order = 46,
                    Description = "Rename or recolor a Keeper NSF folder",
                    Action = context.NsfRndirCommand
                });

            cli.Commands.Add("nsf-rmdir",
                new ParseableCommand<NsfRmdirOptions>
                {
                    Order = 46,
                    Description = "Remove Keeper NSF folder(s)",
                    Action = context.NsfRmdirCommand
                });

            cli.Commands.Add("nsf-move-folder",
                new ParseableCommand<NsfMoveFolderOptions>
                {
                    Order = 46,
                    Description = "Move a Keeper NSF folder to a new parent folder",
                    Action = context.NsfMoveFolderCommand
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
                new ParseableCommand<NsfRecordUpdateOptions>
                {
                    Order = 47,
                    Description = "Update a Keeper NSF record",
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

            cli.Commands.Add("nsf-move-record",
                new ParseableCommand<NsfMoveRecordOptions>
                {
                    Order = 47,
                    Description = "Move a Keeper NSF record between folders",
                    Action = context.NsfMoveRecordCommand
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
    }
}

